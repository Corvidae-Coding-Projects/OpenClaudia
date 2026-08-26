//! Explicit environment-variable schema for [`super::AppConfig`].
//!
//! Environment names are never rewritten into configuration paths. Each
//! accepted name is registered against one typed field, parser, sensitivity,
//! precedence position, and deprecation state. The canonical spelling uses
//! `__` between configuration levels and `_` only between words inside a
//! level. Exact legacy spellings remain accepted so existing deployments can
//! migrate without the old, ambiguous underscore heuristic.

use std::collections::{BTreeMap, HashMap};
use std::ffi::{OsStr, OsString};
use std::num::NonZeroU32;

use thiserror::Error;

#[cfg(test)]
use super::{
    AppConfig, BlastRadiusConfig, DiffMonitorConfig, GuardrailAction, GuardrailMode,
    QualityGatesConfig, RunAfter, VddMode,
};
use crate::providers::ApiKey;
use crate::secrets::SensitiveHeaders;

pub(super) const MAX_ENVIRONMENT_VALUE_BYTES: usize = 64 * 1024;

/// How an accepted environment value is parsed before it reaches typed state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvironmentValueParser {
    /// Strict `true` or `false` boolean.
    Boolean,
    /// Unsigned 16-bit integer.
    U16,
    /// Unsigned 32-bit integer.
    U32,
    /// Unsigned 64-bit integer.
    U64,
    /// Non-negative platform-sized integer.
    Usize,
    /// Non-zero unsigned 32-bit integer.
    NonZeroU32,
    /// Finite 32-bit floating-point number.
    F32,
    /// Non-empty UTF-8 string.
    String,
    /// VDD operating mode (`advisory` or `blocking`).
    VddMode,
    /// Guardrail enforcement mode (`strict` or `advisory`).
    GuardrailMode,
    /// Guardrail failure action.
    GuardrailAction,
    /// Quality-gate execution schedule.
    RunAfter,
    /// Provider reasoning-effort level.
    ReasoningEffort,
    /// Validated provider API key.
    ApiKey,
    /// JSON array of strings.
    JsonStringList,
    /// JSON object whose values are arrays of strings.
    JsonStringListMap,
    /// JSON array of quality-check objects.
    JsonQualityChecks,
    /// JSON object mapping tool names to non-negative integer caps.
    JsonToolCaps,
    /// JSON array deserialized into a set of unique strings.
    JsonStringSet,
    /// JSON object of validated secret header values.
    JsonSensitiveHeaders,
}

/// Diagnostic sensitivity of a configured value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvironmentSecrecy {
    /// Safe to include in ordinary diagnostics.
    Public,
    /// Operationally sensitive but not an authentication secret.
    Sensitive,
    /// Authentication or request-header secret; values must never be logged.
    Secret,
}

/// Source precedence for an environment-provided value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvironmentPrecedence {
    /// Built-in default < project file < trusted home file < environment <
    /// explicit CLI argument.
    AfterFilesBeforeCli,
}

/// Deprecation state of one exact accepted environment name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvironmentDeprecation {
    /// Canonical, documented spelling.
    Current,
    /// Non-OpenClaudia ecosystem spelling retained for compatibility.
    CompatibilityAlias,
    /// Exact legacy `OpenClaudia` spelling retained for migration.
    Deprecated {
        /// Canonical replacement name.
        replacement: String,
    },
}

/// Inspectable metadata for one exact supported environment variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentVariableMetadata {
    /// Exact accepted environment-variable name.
    pub name: String,
    /// Dotted typed configuration field populated by this name.
    pub config_field: String,
    /// Parser applied before the value reaches the configuration builder.
    pub parser: EnvironmentValueParser,
    /// Diagnostic sensitivity classification.
    pub secrecy: EnvironmentSecrecy,
    /// Position in the configuration-source precedence chain.
    pub precedence: EnvironmentPrecedence,
    /// Migration status for this exact spelling.
    pub deprecation: EnvironmentDeprecation,
    /// Whether empty or malformed input must fail closed.
    pub security_relevant: bool,
}

/// Typed failures produced while resolving the process environment.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EnvironmentConfigError {
    /// An `OPENCLAUDIA_`-prefixed variable name is not valid Unicode.
    #[error("OpenClaudia environment variable name contains non-Unicode data")]
    NonUnicodeName,
    /// A registered variable has a non-Unicode value.
    #[error("environment variable {name} contains non-Unicode data")]
    NonUnicodeValue {
        /// Exact registered variable name.
        name: String,
    },
    /// An `OPENCLAUDIA_`-prefixed variable is not owned by any schema.
    #[error("unknown OpenClaudia environment variable {name}")]
    UnknownVariable {
        /// Rejected variable name.
        name: String,
    },
    /// More than one exact name attempts to configure one field.
    #[error("environment variables {names:?} ambiguously configure {config_field}")]
    AmbiguousField {
        /// Dotted typed field with multiple candidate values.
        config_field: String,
        /// Sorted exact variable names that collided.
        names: Vec<String>,
    },
    /// A value exceeds the bounded input size.
    #[error("environment variable {name} exceeds the {max_bytes}-byte value limit")]
    ValueTooLong {
        /// Exact registered variable name.
        name: String,
        /// Maximum accepted byte length.
        max_bytes: usize,
    },
    /// A registered value does not satisfy its declared parser.
    #[error(
        "environment variable {name} is invalid for {config_field}: expected {expected}: {reason}"
    )]
    InvalidValue {
        /// Exact registered variable name.
        name: String,
        /// Dotted typed field the value was intended to populate.
        config_field: String,
        /// Public description of the accepted input shape.
        expected: &'static str,
        /// Redacted parser failure.
        reason: String,
    },
    /// A test-only typed application target lacks a built-in provider.
    #[error("environment variable {name} targets unavailable provider configuration {provider}")]
    MissingProvider {
        /// Exact registered variable name.
        name: String,
        /// Missing provider key.
        provider: String,
    },
    /// A registry descriptor contains a builder path that cannot be applied.
    #[error("typed environment registry path {config_field} is invalid: {reason}")]
    InvalidRegistryPath {
        /// Dotted registry path.
        config_field: String,
        /// Builder conversion failure.
        reason: String,
    },
    /// One exact name has more than one registry owner.
    #[error("environment variable {name} is registered for both {first_field} and {second_field}")]
    DuplicateRegistration {
        /// Duplicated exact variable name.
        name: String,
        /// First owning dotted field.
        first_field: String,
        /// Conflicting owning dotted field.
        second_field: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ProviderField {
    ApiKey,
    BaseUrl,
    Model,
    Headers,
    ThinkingEnabled,
    ThinkingBudgetTokens,
    ThinkingPreserveAcrossTurns,
    ThinkingReasoningEffort,
    ThinkingAdaptive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ConfigField {
    ProxyPort,
    ProxyHost,
    ProxyTarget,
    ProxyMaxResponseBytes,
    Provider {
        name: &'static str,
        field: ProviderField,
    },
    SessionTimeoutMinutes,
    SessionPersistPath,
    SessionMaxTurns,
    SessionTokenTrackingEnabled,
    SessionTokenTrackingLogUsage,
    SessionTokenTrackingWarnThreshold,
    SessionTokenTrackingMaxOutputTokens,
    VddEnabled,
    VddMode,
    VddAdversaryProvider,
    VddAdversaryModel,
    VddAdversaryApiKey,
    VddAdversaryTemperature,
    VddAdversaryMaxTokens,
    VddAdversaryRequestTimeoutSeconds,
    VddThresholdsMaxIterations,
    VddThresholdsFalsePositiveRate,
    VddThresholdsMinIterations,
    VddStaticAnalysisEnabled,
    VddStaticAnalysisAutoDetect,
    VddStaticAnalysisCommands,
    VddStaticAnalysisTimeoutSeconds,
    VddTrackingPersist,
    VddTrackingPath,
    VddTrackingLogAdversaryResponses,
    GuardrailsBlastRadiusEnabled,
    GuardrailsBlastRadiusMode,
    GuardrailsBlastRadiusAllowedPaths,
    GuardrailsBlastRadiusDeniedPaths,
    GuardrailsBlastRadiusMaxFilesPerRun,
    GuardrailsBlastRadiusMaxLinesPerRun,
    GuardrailsBlastRadiusMaxToolCallsPerRun,
    GuardrailsBlastRadiusMaxMutationsPerRun,
    GuardrailsDiffMonitorEnabled,
    GuardrailsDiffMonitorMaxLinesChanged,
    GuardrailsDiffMonitorMaxFilesChanged,
    GuardrailsDiffMonitorAction,
    GuardrailsQualityGatesEnabled,
    GuardrailsQualityGatesRunAfter,
    GuardrailsQualityGatesFailAction,
    GuardrailsQualityGatesChecks,
    GuardrailsQualityGatesTimeoutSeconds,
    PermissionsEnabled,
    PermissionsDefaultAllow,
    PermissionsMcp,
    MemoryAutomaticLearningEnabled,
    MemoryTeamId,
    MemoryTeamMemoryPath,
    WebFetchDistillationEnabled,
    WebFetchMaxDistillationBytes,
    WebFetchDistillationProvider,
    WebFetchDistillationModel,
    WebFetchPreapprovedDomains,
    WebFetchExactPrivateOrigins,
    PolicyMaxRequestTokens,
    PolicyMaxSessionTokens,
    PolicyToolCaps,
    PolicyModelAllowlist,
}

#[derive(Clone, Copy)]
struct AliasDefinition {
    name: &'static str,
    compatibility: bool,
}

#[derive(Clone, Copy)]
struct FieldDefinition {
    field: ConfigField,
    config_field: &'static str,
    canonical: &'static str,
    aliases: &'static [AliasDefinition],
    parser: EnvironmentValueParser,
    secrecy: EnvironmentSecrecy,
    security_relevant: bool,
}

#[derive(Clone)]
struct RegisteredVariable {
    name: String,
    deprecation: EnvironmentDeprecation,
}

#[derive(Clone)]
struct RegisteredField {
    field: ConfigField,
    config_field: String,
    variables: Vec<RegisteredVariable>,
    parser: EnvironmentValueParser,
    secrecy: EnvironmentSecrecy,
    security_relevant: bool,
}

macro_rules! field {
    ($field:expr, $path:literal, $canonical:literal, $legacy:literal, $parser:ident, $secrecy:ident, $security:expr) => {
        FieldDefinition {
            field: $field,
            config_field: $path,
            canonical: $canonical,
            aliases: &[AliasDefinition {
                name: $legacy,
                compatibility: false,
            }],
            parser: EnvironmentValueParser::$parser,
            secrecy: EnvironmentSecrecy::$secrecy,
            security_relevant: $security,
        }
    };
}

const APP_FIELDS: &[FieldDefinition] = &[
    field!(
        ConfigField::ProxyPort,
        "proxy.port",
        "OPENCLAUDIA_PROXY__PORT",
        "OPENCLAUDIA_PROXY_PORT",
        U16,
        Public,
        true
    ),
    field!(
        ConfigField::ProxyHost,
        "proxy.host",
        "OPENCLAUDIA_PROXY__HOST",
        "OPENCLAUDIA_PROXY_HOST",
        String,
        Sensitive,
        true
    ),
    field!(
        ConfigField::ProxyTarget,
        "proxy.target",
        "OPENCLAUDIA_PROXY__TARGET",
        "OPENCLAUDIA_PROXY_TARGET",
        String,
        Public,
        true
    ),
    field!(
        ConfigField::ProxyMaxResponseBytes,
        "proxy.max_response_bytes",
        "OPENCLAUDIA_PROXY__MAX_RESPONSE_BYTES",
        "OPENCLAUDIA_PROXY_MAX_RESPONSE_BYTES",
        Usize,
        Public,
        true
    ),
    field!(
        ConfigField::SessionTimeoutMinutes,
        "session.timeout_minutes",
        "OPENCLAUDIA_SESSION__TIMEOUT_MINUTES",
        "OPENCLAUDIA_SESSION_TIMEOUT_MINUTES",
        U64,
        Public,
        true
    ),
    field!(
        ConfigField::SessionPersistPath,
        "session.persist_path",
        "OPENCLAUDIA_SESSION__PERSIST_PATH",
        "OPENCLAUDIA_SESSION_PERSIST_PATH",
        String,
        Sensitive,
        true
    ),
    field!(
        ConfigField::SessionMaxTurns,
        "session.max_turns",
        "OPENCLAUDIA_SESSION__MAX_TURNS",
        "OPENCLAUDIA_SESSION_MAX_TURNS",
        U32,
        Public,
        true
    ),
    field!(
        ConfigField::SessionTokenTrackingEnabled,
        "session.token_tracking.enabled",
        "OPENCLAUDIA_SESSION__TOKEN_TRACKING__ENABLED",
        "OPENCLAUDIA_SESSION_TOKEN_TRACKING_ENABLED",
        Boolean,
        Public,
        false
    ),
    field!(
        ConfigField::SessionTokenTrackingLogUsage,
        "session.token_tracking.log_usage",
        "OPENCLAUDIA_SESSION__TOKEN_TRACKING__LOG_USAGE",
        "OPENCLAUDIA_SESSION_TOKEN_TRACKING_LOG_USAGE",
        Boolean,
        Public,
        false
    ),
    field!(
        ConfigField::SessionTokenTrackingWarnThreshold,
        "session.token_tracking.warn_threshold",
        "OPENCLAUDIA_SESSION__TOKEN_TRACKING__WARN_THRESHOLD",
        "OPENCLAUDIA_SESSION_TOKEN_TRACKING_WARN_THRESHOLD",
        F32,
        Public,
        true
    ),
    field!(
        ConfigField::SessionTokenTrackingMaxOutputTokens,
        "session.token_tracking.max_output_tokens",
        "OPENCLAUDIA_SESSION__TOKEN_TRACKING__MAX_OUTPUT_TOKENS",
        "OPENCLAUDIA_SESSION_TOKEN_TRACKING_MAX_OUTPUT_TOKENS",
        U32,
        Public,
        true
    ),
    field!(
        ConfigField::VddEnabled,
        "vdd.enabled",
        "OPENCLAUDIA_VDD__ENABLED",
        "OPENCLAUDIA_VDD_ENABLED",
        Boolean,
        Public,
        true
    ),
    field!(
        ConfigField::VddMode,
        "vdd.mode",
        "OPENCLAUDIA_VDD__MODE",
        "OPENCLAUDIA_VDD_MODE",
        VddMode,
        Public,
        true
    ),
    field!(
        ConfigField::VddAdversaryProvider,
        "vdd.adversary.provider",
        "OPENCLAUDIA_VDD__ADVERSARY__PROVIDER",
        "OPENCLAUDIA_VDD_ADVERSARY_PROVIDER",
        String,
        Public,
        true
    ),
    field!(
        ConfigField::VddAdversaryModel,
        "vdd.adversary.model",
        "OPENCLAUDIA_VDD__ADVERSARY__MODEL",
        "OPENCLAUDIA_VDD_ADVERSARY_MODEL",
        String,
        Public,
        true
    ),
    field!(
        ConfigField::VddAdversaryApiKey,
        "vdd.adversary.api_key",
        "OPENCLAUDIA_VDD__ADVERSARY__API_KEY",
        "OPENCLAUDIA_VDD_ADVERSARY_API_KEY",
        ApiKey,
        Secret,
        true
    ),
    field!(
        ConfigField::VddAdversaryTemperature,
        "vdd.adversary.temperature",
        "OPENCLAUDIA_VDD__ADVERSARY__TEMPERATURE",
        "OPENCLAUDIA_VDD_ADVERSARY_TEMPERATURE",
        F32,
        Public,
        true
    ),
    field!(
        ConfigField::VddAdversaryMaxTokens,
        "vdd.adversary.max_tokens",
        "OPENCLAUDIA_VDD__ADVERSARY__MAX_TOKENS",
        "OPENCLAUDIA_VDD_ADVERSARY_MAX_TOKENS",
        U32,
        Public,
        true
    ),
    field!(
        ConfigField::VddAdversaryRequestTimeoutSeconds,
        "vdd.adversary.request_timeout_seconds",
        "OPENCLAUDIA_VDD__ADVERSARY__REQUEST_TIMEOUT_SECONDS",
        "OPENCLAUDIA_VDD_ADVERSARY_REQUEST_TIMEOUT_SECONDS",
        U64,
        Public,
        true
    ),
    field!(
        ConfigField::VddThresholdsMaxIterations,
        "vdd.thresholds.max_iterations",
        "OPENCLAUDIA_VDD__THRESHOLDS__MAX_ITERATIONS",
        "OPENCLAUDIA_VDD_THRESHOLDS_MAX_ITERATIONS",
        U32,
        Public,
        true
    ),
    field!(
        ConfigField::VddThresholdsFalsePositiveRate,
        "vdd.thresholds.false_positive_rate",
        "OPENCLAUDIA_VDD__THRESHOLDS__FALSE_POSITIVE_RATE",
        "OPENCLAUDIA_VDD_THRESHOLDS_FALSE_POSITIVE_RATE",
        F32,
        Public,
        true
    ),
    field!(
        ConfigField::VddThresholdsMinIterations,
        "vdd.thresholds.min_iterations",
        "OPENCLAUDIA_VDD__THRESHOLDS__MIN_ITERATIONS",
        "OPENCLAUDIA_VDD_THRESHOLDS_MIN_ITERATIONS",
        U32,
        Public,
        true
    ),
    field!(
        ConfigField::VddStaticAnalysisEnabled,
        "vdd.static_analysis.enabled",
        "OPENCLAUDIA_VDD__STATIC_ANALYSIS__ENABLED",
        "OPENCLAUDIA_VDD_STATIC_ANALYSIS_ENABLED",
        Boolean,
        Public,
        true
    ),
    field!(
        ConfigField::VddStaticAnalysisAutoDetect,
        "vdd.static_analysis.auto_detect",
        "OPENCLAUDIA_VDD__STATIC_ANALYSIS__AUTO_DETECT",
        "OPENCLAUDIA_VDD_STATIC_ANALYSIS_AUTO_DETECT",
        Boolean,
        Public,
        true
    ),
    field!(
        ConfigField::VddStaticAnalysisCommands,
        "vdd.static_analysis.commands",
        "OPENCLAUDIA_VDD__STATIC_ANALYSIS__COMMANDS",
        "OPENCLAUDIA_VDD_STATIC_ANALYSIS_COMMANDS",
        JsonStringList,
        Sensitive,
        true
    ),
    field!(
        ConfigField::VddStaticAnalysisTimeoutSeconds,
        "vdd.static_analysis.timeout_seconds",
        "OPENCLAUDIA_VDD__STATIC_ANALYSIS__TIMEOUT_SECONDS",
        "OPENCLAUDIA_VDD_STATIC_ANALYSIS_TIMEOUT_SECONDS",
        U64,
        Public,
        true
    ),
    field!(
        ConfigField::VddTrackingPersist,
        "vdd.tracking.persist",
        "OPENCLAUDIA_VDD__TRACKING__PERSIST",
        "OPENCLAUDIA_VDD_TRACKING_PERSIST",
        Boolean,
        Public,
        true
    ),
    field!(
        ConfigField::VddTrackingPath,
        "vdd.tracking.path",
        "OPENCLAUDIA_VDD__TRACKING__PATH",
        "OPENCLAUDIA_VDD_TRACKING_PATH",
        String,
        Sensitive,
        true
    ),
    field!(
        ConfigField::VddTrackingLogAdversaryResponses,
        "vdd.tracking.log_adversary_responses",
        "OPENCLAUDIA_VDD__TRACKING__LOG_ADVERSARY_RESPONSES",
        "OPENCLAUDIA_VDD_TRACKING_LOG_ADVERSARY_RESPONSES",
        Boolean,
        Sensitive,
        true
    ),
    field!(
        ConfigField::GuardrailsBlastRadiusEnabled,
        "guardrails.blast_radius.enabled",
        "OPENCLAUDIA_GUARDRAILS__BLAST_RADIUS__ENABLED",
        "OPENCLAUDIA_GUARDRAILS_BLAST_RADIUS_ENABLED",
        Boolean,
        Public,
        true
    ),
    field!(
        ConfigField::GuardrailsBlastRadiusMode,
        "guardrails.blast_radius.mode",
        "OPENCLAUDIA_GUARDRAILS__BLAST_RADIUS__MODE",
        "OPENCLAUDIA_GUARDRAILS_BLAST_RADIUS_MODE",
        GuardrailMode,
        Public,
        true
    ),
    field!(
        ConfigField::GuardrailsBlastRadiusAllowedPaths,
        "guardrails.blast_radius.allowed_paths",
        "OPENCLAUDIA_GUARDRAILS__BLAST_RADIUS__ALLOWED_PATHS",
        "OPENCLAUDIA_GUARDRAILS_BLAST_RADIUS_ALLOWED_PATHS",
        JsonStringList,
        Sensitive,
        true
    ),
    field!(
        ConfigField::GuardrailsBlastRadiusDeniedPaths,
        "guardrails.blast_radius.denied_paths",
        "OPENCLAUDIA_GUARDRAILS__BLAST_RADIUS__DENIED_PATHS",
        "OPENCLAUDIA_GUARDRAILS_BLAST_RADIUS_DENIED_PATHS",
        JsonStringList,
        Sensitive,
        true
    ),
    field!(
        ConfigField::GuardrailsBlastRadiusMaxFilesPerRun,
        "guardrails.blast_radius.max_files_per_run",
        "OPENCLAUDIA_GUARDRAILS__BLAST_RADIUS__MAX_FILES_PER_RUN",
        "OPENCLAUDIA_GUARDRAILS_BLAST_RADIUS_MAX_FILES_PER_RUN",
        NonZeroU32,
        Public,
        true
    ),
    field!(
        ConfigField::GuardrailsBlastRadiusMaxLinesPerRun,
        "guardrails.blast_radius.max_lines_per_run",
        "OPENCLAUDIA_GUARDRAILS__BLAST_RADIUS__MAX_LINES_PER_RUN",
        "OPENCLAUDIA_GUARDRAILS_BLAST_RADIUS_MAX_LINES_PER_RUN",
        NonZeroU32,
        Public,
        true
    ),
    field!(
        ConfigField::GuardrailsBlastRadiusMaxToolCallsPerRun,
        "guardrails.blast_radius.max_tool_calls_per_run",
        "OPENCLAUDIA_GUARDRAILS__BLAST_RADIUS__MAX_TOOL_CALLS_PER_RUN",
        "OPENCLAUDIA_GUARDRAILS_BLAST_RADIUS_MAX_TOOL_CALLS_PER_RUN",
        NonZeroU32,
        Public,
        true
    ),
    field!(
        ConfigField::GuardrailsBlastRadiusMaxMutationsPerRun,
        "guardrails.blast_radius.max_mutations_per_run",
        "OPENCLAUDIA_GUARDRAILS__BLAST_RADIUS__MAX_MUTATIONS_PER_RUN",
        "OPENCLAUDIA_GUARDRAILS_BLAST_RADIUS_MAX_MUTATIONS_PER_RUN",
        NonZeroU32,
        Public,
        true
    ),
    field!(
        ConfigField::GuardrailsDiffMonitorEnabled,
        "guardrails.diff_monitor.enabled",
        "OPENCLAUDIA_GUARDRAILS__DIFF_MONITOR__ENABLED",
        "OPENCLAUDIA_GUARDRAILS_DIFF_MONITOR_ENABLED",
        Boolean,
        Public,
        true
    ),
    field!(
        ConfigField::GuardrailsDiffMonitorMaxLinesChanged,
        "guardrails.diff_monitor.max_lines_changed",
        "OPENCLAUDIA_GUARDRAILS__DIFF_MONITOR__MAX_LINES_CHANGED",
        "OPENCLAUDIA_GUARDRAILS_DIFF_MONITOR_MAX_LINES_CHANGED",
        U32,
        Public,
        true
    ),
    field!(
        ConfigField::GuardrailsDiffMonitorMaxFilesChanged,
        "guardrails.diff_monitor.max_files_changed",
        "OPENCLAUDIA_GUARDRAILS__DIFF_MONITOR__MAX_FILES_CHANGED",
        "OPENCLAUDIA_GUARDRAILS_DIFF_MONITOR_MAX_FILES_CHANGED",
        U32,
        Public,
        true
    ),
    field!(
        ConfigField::GuardrailsDiffMonitorAction,
        "guardrails.diff_monitor.action",
        "OPENCLAUDIA_GUARDRAILS__DIFF_MONITOR__ACTION",
        "OPENCLAUDIA_GUARDRAILS_DIFF_MONITOR_ACTION",
        GuardrailAction,
        Public,
        true
    ),
    field!(
        ConfigField::GuardrailsQualityGatesEnabled,
        "guardrails.quality_gates.enabled",
        "OPENCLAUDIA_GUARDRAILS__QUALITY_GATES__ENABLED",
        "OPENCLAUDIA_GUARDRAILS_QUALITY_GATES_ENABLED",
        Boolean,
        Public,
        true
    ),
    field!(
        ConfigField::GuardrailsQualityGatesRunAfter,
        "guardrails.quality_gates.run_after",
        "OPENCLAUDIA_GUARDRAILS__QUALITY_GATES__RUN_AFTER",
        "OPENCLAUDIA_GUARDRAILS_QUALITY_GATES_RUN_AFTER",
        RunAfter,
        Public,
        true
    ),
    field!(
        ConfigField::GuardrailsQualityGatesFailAction,
        "guardrails.quality_gates.fail_action",
        "OPENCLAUDIA_GUARDRAILS__QUALITY_GATES__FAIL_ACTION",
        "OPENCLAUDIA_GUARDRAILS_QUALITY_GATES_FAIL_ACTION",
        GuardrailAction,
        Public,
        true
    ),
    field!(
        ConfigField::GuardrailsQualityGatesChecks,
        "guardrails.quality_gates.checks",
        "OPENCLAUDIA_GUARDRAILS__QUALITY_GATES__CHECKS",
        "OPENCLAUDIA_GUARDRAILS_QUALITY_GATES_CHECKS",
        JsonQualityChecks,
        Sensitive,
        true
    ),
    field!(
        ConfigField::GuardrailsQualityGatesTimeoutSeconds,
        "guardrails.quality_gates.timeout_seconds",
        "OPENCLAUDIA_GUARDRAILS__QUALITY_GATES__TIMEOUT_SECONDS",
        "OPENCLAUDIA_GUARDRAILS_QUALITY_GATES_TIMEOUT_SECONDS",
        U64,
        Public,
        true
    ),
    field!(
        ConfigField::PermissionsEnabled,
        "permissions.enabled",
        "OPENCLAUDIA_PERMISSIONS__ENABLED",
        "OPENCLAUDIA_PERMISSIONS_ENABLED",
        Boolean,
        Public,
        true
    ),
    field!(
        ConfigField::PermissionsDefaultAllow,
        "permissions.default_allow",
        "OPENCLAUDIA_PERMISSIONS__DEFAULT_ALLOW",
        "OPENCLAUDIA_PERMISSIONS_DEFAULT_ALLOW",
        JsonStringList,
        Sensitive,
        true
    ),
    field!(
        ConfigField::PermissionsMcp,
        "permissions.mcp",
        "OPENCLAUDIA_PERMISSIONS__MCP",
        "OPENCLAUDIA_PERMISSIONS_MCP",
        JsonStringListMap,
        Sensitive,
        true
    ),
    field!(
        ConfigField::MemoryAutomaticLearningEnabled,
        "memory.automatic_learning_enabled",
        "OPENCLAUDIA_MEMORY__AUTOMATIC_LEARNING_ENABLED",
        "OPENCLAUDIA_MEMORY_AUTOMATIC_LEARNING_ENABLED",
        Boolean,
        Public,
        true
    ),
    field!(
        ConfigField::MemoryTeamId,
        "memory.team_id",
        "OPENCLAUDIA_MEMORY__TEAM_ID",
        "OPENCLAUDIA_MEMORY_TEAM_ID",
        String,
        Public,
        true
    ),
    field!(
        ConfigField::MemoryTeamMemoryPath,
        "memory.team_memory_path",
        "OPENCLAUDIA_MEMORY__TEAM_MEMORY_PATH",
        "OPENCLAUDIA_MEMORY_TEAM_MEMORY_PATH",
        String,
        Sensitive,
        true
    ),
    field!(
        ConfigField::WebFetchDistillationEnabled,
        "web_fetch.distillation_enabled",
        "OPENCLAUDIA_WEB_FETCH__DISTILLATION_ENABLED",
        "OPENCLAUDIA_WEB_FETCH_DISTILLATION_ENABLED",
        Boolean,
        Public,
        true
    ),
    field!(
        ConfigField::WebFetchMaxDistillationBytes,
        "web_fetch.max_distillation_bytes",
        "OPENCLAUDIA_WEB_FETCH__MAX_DISTILLATION_BYTES",
        "OPENCLAUDIA_WEB_FETCH_MAX_DISTILLATION_BYTES",
        Usize,
        Public,
        true
    ),
    field!(
        ConfigField::WebFetchDistillationProvider,
        "web_fetch.distillation_provider",
        "OPENCLAUDIA_WEB_FETCH__DISTILLATION_PROVIDER",
        "OPENCLAUDIA_WEB_FETCH_DISTILLATION_PROVIDER",
        String,
        Public,
        true
    ),
    field!(
        ConfigField::WebFetchDistillationModel,
        "web_fetch.distillation_model",
        "OPENCLAUDIA_WEB_FETCH__DISTILLATION_MODEL",
        "OPENCLAUDIA_WEB_FETCH_DISTILLATION_MODEL",
        String,
        Public,
        true
    ),
    field!(
        ConfigField::WebFetchPreapprovedDomains,
        "web_fetch.preapproved_domains",
        "OPENCLAUDIA_WEB_FETCH__PREAPPROVED_DOMAINS",
        "OPENCLAUDIA_WEB_FETCH_PREAPPROVED_DOMAINS",
        JsonStringList,
        Sensitive,
        true
    ),
    field!(
        ConfigField::WebFetchExactPrivateOrigins,
        "web_fetch.exact_private_origins",
        "OPENCLAUDIA_WEB_FETCH__EXACT_PRIVATE_ORIGINS",
        "OPENCLAUDIA_WEB_FETCH_EXACT_PRIVATE_ORIGINS",
        JsonStringList,
        Sensitive,
        true
    ),
    field!(
        ConfigField::PolicyMaxRequestTokens,
        "policy.max_request_tokens",
        "OPENCLAUDIA_POLICY__MAX_REQUEST_TOKENS",
        "OPENCLAUDIA_POLICY_MAX_REQUEST_TOKENS",
        Usize,
        Public,
        true
    ),
    field!(
        ConfigField::PolicyMaxSessionTokens,
        "policy.max_session_tokens",
        "OPENCLAUDIA_POLICY__MAX_SESSION_TOKENS",
        "OPENCLAUDIA_POLICY_MAX_SESSION_TOKENS",
        Usize,
        Public,
        true
    ),
    field!(
        ConfigField::PolicyToolCaps,
        "policy.tool_caps",
        "OPENCLAUDIA_POLICY__TOOL_CAPS",
        "OPENCLAUDIA_POLICY_TOOL_CAPS",
        JsonToolCaps,
        Sensitive,
        true
    ),
    field!(
        ConfigField::PolicyModelAllowlist,
        "policy.model_allowlist",
        "OPENCLAUDIA_POLICY__MODEL_ALLOWLIST",
        "OPENCLAUDIA_POLICY_MODEL_ALLOWLIST",
        JsonStringSet,
        Sensitive,
        true
    ),
];

#[derive(Clone, Copy)]
struct ProviderNamespace {
    config_name: &'static str,
    env_name: &'static str,
    legacy_env_name: &'static str,
    additional_legacy_env_name: Option<&'static str>,
    api_key_aliases: &'static [&'static str],
}

const PROVIDERS: &[ProviderNamespace] = &[
    ProviderNamespace {
        config_name: "anthropic",
        env_name: "ANTHROPIC",
        legacy_env_name: "ANTHROPIC",
        additional_legacy_env_name: None,
        api_key_aliases: &["ANTHROPIC_API_KEY"],
    },
    ProviderNamespace {
        config_name: "openai",
        env_name: "OPENAI",
        legacy_env_name: "OPENAI",
        additional_legacy_env_name: None,
        api_key_aliases: &["OPENAI_API_KEY"],
    },
    ProviderNamespace {
        config_name: "google",
        env_name: "GOOGLE",
        legacy_env_name: "GOOGLE",
        additional_legacy_env_name: None,
        api_key_aliases: &["GOOGLE_API_KEY", "GEMINI_API_KEY"],
    },
    ProviderNamespace {
        config_name: "zai",
        env_name: "ZAI",
        legacy_env_name: "ZAI",
        additional_legacy_env_name: None,
        api_key_aliases: &["ZAI_API_KEY"],
    },
    ProviderNamespace {
        config_name: "deepseek",
        env_name: "DEEPSEEK",
        legacy_env_name: "DEEPSEEK",
        additional_legacy_env_name: None,
        api_key_aliases: &["DEEPSEEK_API_KEY"],
    },
    ProviderNamespace {
        config_name: "qwen",
        env_name: "QWEN",
        legacy_env_name: "QWEN",
        additional_legacy_env_name: None,
        api_key_aliases: &["QWEN_API_KEY", "DASHSCOPE_API_KEY", "ALIYUN_API_KEY"],
    },
    ProviderNamespace {
        config_name: "kimi",
        env_name: "KIMI",
        legacy_env_name: "KIMI",
        additional_legacy_env_name: None,
        api_key_aliases: &["KIMI_API_KEY", "MOONSHOT_API_KEY"],
    },
    ProviderNamespace {
        config_name: "minimax",
        env_name: "MINIMAX",
        legacy_env_name: "MINIMAX",
        additional_legacy_env_name: None,
        api_key_aliases: &["MINIMAX_API_KEY"],
    },
    ProviderNamespace {
        config_name: "openrouter",
        env_name: "OPENROUTER",
        legacy_env_name: "OPENROUTER",
        additional_legacy_env_name: None,
        api_key_aliases: &["OPENROUTER_API_KEY", "OPEN_ROUTER_API_KEY"],
    },
    ProviderNamespace {
        config_name: "opencode",
        env_name: "OPENCODE",
        legacy_env_name: "OPENCODE",
        additional_legacy_env_name: None,
        api_key_aliases: &["OPENCODE_API_KEY", "OPENCODE_GO_API_KEY"],
    },
    ProviderNamespace {
        config_name: "openai-compatible",
        env_name: "OPENAI_COMPATIBLE",
        legacy_env_name: "OPENAI_COMPATIBLE",
        additional_legacy_env_name: None,
        api_key_aliases: &["OPENAI_COMPATIBLE_API_KEY", "API_KEY"],
    },
    ProviderNamespace {
        config_name: "ollama",
        env_name: "OLLAMA",
        legacy_env_name: "OLLAMA",
        additional_legacy_env_name: None,
        api_key_aliases: &[],
    },
    ProviderNamespace {
        config_name: "local",
        env_name: "LOCAL",
        legacy_env_name: "LOCAL",
        additional_legacy_env_name: None,
        api_key_aliases: &[],
    },
    ProviderNamespace {
        config_name: "lmstudio",
        env_name: "LMSTUDIO",
        legacy_env_name: "LMSTUDIO",
        additional_legacy_env_name: None,
        api_key_aliases: &[],
    },
    ProviderNamespace {
        config_name: "localai",
        env_name: "LOCALAI",
        legacy_env_name: "LOCALAI",
        additional_legacy_env_name: None,
        api_key_aliases: &[],
    },
    ProviderNamespace {
        config_name: "text-generation-webui",
        env_name: "TEXT_GENERATION_WEBUI",
        legacy_env_name: "TEXT-GENERATION-WEBUI",
        additional_legacy_env_name: Some("TEXT_GENERATION_WEBUI"),
        api_key_aliases: &[],
    },
];

#[derive(Clone, Copy)]
struct ProviderFieldDefinition {
    field: ProviderField,
    path: &'static str,
    env_path: &'static str,
    legacy_env_path: &'static str,
    parser: EnvironmentValueParser,
    secrecy: EnvironmentSecrecy,
    security_relevant: bool,
}

const PROVIDER_FIELDS: &[ProviderFieldDefinition] = &[
    ProviderFieldDefinition {
        field: ProviderField::ApiKey,
        path: "api_key",
        env_path: "API_KEY",
        legacy_env_path: "API_KEY",
        parser: EnvironmentValueParser::ApiKey,
        secrecy: EnvironmentSecrecy::Secret,
        security_relevant: true,
    },
    ProviderFieldDefinition {
        field: ProviderField::BaseUrl,
        path: "base_url",
        env_path: "BASE_URL",
        legacy_env_path: "BASE_URL",
        parser: EnvironmentValueParser::String,
        secrecy: EnvironmentSecrecy::Sensitive,
        security_relevant: true,
    },
    ProviderFieldDefinition {
        field: ProviderField::Model,
        path: "model",
        env_path: "MODEL",
        legacy_env_path: "MODEL",
        parser: EnvironmentValueParser::String,
        secrecy: EnvironmentSecrecy::Public,
        security_relevant: false,
    },
    ProviderFieldDefinition {
        field: ProviderField::Headers,
        path: "headers",
        env_path: "HEADERS",
        legacy_env_path: "HEADERS",
        parser: EnvironmentValueParser::JsonSensitiveHeaders,
        secrecy: EnvironmentSecrecy::Secret,
        security_relevant: true,
    },
    ProviderFieldDefinition {
        field: ProviderField::ThinkingEnabled,
        path: "thinking.enabled",
        env_path: "THINKING__ENABLED",
        legacy_env_path: "THINKING_ENABLED",
        parser: EnvironmentValueParser::Boolean,
        secrecy: EnvironmentSecrecy::Public,
        security_relevant: false,
    },
    ProviderFieldDefinition {
        field: ProviderField::ThinkingBudgetTokens,
        path: "thinking.budget_tokens",
        env_path: "THINKING__BUDGET_TOKENS",
        legacy_env_path: "THINKING_BUDGET_TOKENS",
        parser: EnvironmentValueParser::U32,
        secrecy: EnvironmentSecrecy::Public,
        security_relevant: true,
    },
    ProviderFieldDefinition {
        field: ProviderField::ThinkingPreserveAcrossTurns,
        path: "thinking.preserve_across_turns",
        env_path: "THINKING__PRESERVE_ACROSS_TURNS",
        legacy_env_path: "THINKING_PRESERVE_ACROSS_TURNS",
        parser: EnvironmentValueParser::Boolean,
        secrecy: EnvironmentSecrecy::Public,
        security_relevant: false,
    },
    ProviderFieldDefinition {
        field: ProviderField::ThinkingReasoningEffort,
        path: "thinking.reasoning_effort",
        env_path: "THINKING__REASONING_EFFORT",
        legacy_env_path: "THINKING_REASONING_EFFORT",
        parser: EnvironmentValueParser::ReasoningEffort,
        secrecy: EnvironmentSecrecy::Public,
        security_relevant: false,
    },
    ProviderFieldDefinition {
        field: ProviderField::ThinkingAdaptive,
        path: "thinking.adaptive",
        env_path: "THINKING__ADAPTIVE",
        legacy_env_path: "THINKING_ADAPTIVE",
        parser: EnvironmentValueParser::Boolean,
        secrecy: EnvironmentSecrecy::Public,
        security_relevant: false,
    },
];

fn registry() -> Vec<RegisteredField> {
    let mut fields = APP_FIELDS
        .iter()
        .map(|definition| RegisteredField {
            field: definition.field,
            config_field: definition.config_field.to_string(),
            variables: std::iter::once(RegisteredVariable {
                name: definition.canonical.to_string(),
                deprecation: EnvironmentDeprecation::Current,
            })
            .chain(definition.aliases.iter().map(|alias| RegisteredVariable {
                name: alias.name.to_string(),
                deprecation: if alias.compatibility {
                    EnvironmentDeprecation::CompatibilityAlias
                } else {
                    EnvironmentDeprecation::Deprecated {
                        replacement: definition.canonical.to_string(),
                    }
                },
            }))
            .collect(),
            parser: definition.parser,
            secrecy: definition.secrecy,
            security_relevant: definition.security_relevant,
        })
        .collect::<Vec<_>>();

    for provider in PROVIDERS {
        for provider_field in PROVIDER_FIELDS {
            let canonical = format!(
                "OPENCLAUDIA_PROVIDERS__{}__{}",
                provider.env_name, provider_field.env_path
            );
            let mut variables = vec![RegisteredVariable {
                name: canonical.clone(),
                deprecation: EnvironmentDeprecation::Current,
            }];
            let legacy = format!(
                "OPENCLAUDIA_PROVIDERS_{}_{}",
                provider.legacy_env_name, provider_field.legacy_env_path
            );
            variables.push(RegisteredVariable {
                name: legacy,
                deprecation: EnvironmentDeprecation::Deprecated {
                    replacement: canonical.clone(),
                },
            });
            if let Some(additional) = provider.additional_legacy_env_name {
                variables.push(RegisteredVariable {
                    name: format!(
                        "OPENCLAUDIA_PROVIDERS_{}_{}",
                        additional, provider_field.legacy_env_path
                    ),
                    deprecation: EnvironmentDeprecation::Deprecated {
                        replacement: canonical.clone(),
                    },
                });
            }
            if provider_field.field == ProviderField::ApiKey {
                variables.extend(
                    provider
                        .api_key_aliases
                        .iter()
                        .map(|name| RegisteredVariable {
                            name: (*name).to_string(),
                            deprecation: EnvironmentDeprecation::CompatibilityAlias,
                        }),
                );
            }
            fields.push(RegisteredField {
                field: ConfigField::Provider {
                    name: provider.config_name,
                    field: provider_field.field,
                },
                config_field: format!("providers.{}.{}", provider.config_name, provider_field.path),
                variables,
                parser: provider_field.parser,
                secrecy: provider_field.secrecy,
                security_relevant: provider_field.security_relevant,
            });
        }
    }
    fields
}

/// Return the complete, deterministic environment-variable conformance map.
#[must_use]
pub fn environment_variable_metadata() -> Vec<EnvironmentVariableMetadata> {
    let mut metadata = registry()
        .into_iter()
        .flat_map(|field| {
            field
                .variables
                .into_iter()
                .map(move |variable| EnvironmentVariableMetadata {
                    name: variable.name,
                    config_field: field.config_field.clone(),
                    parser: field.parser,
                    secrecy: field.secrecy,
                    precedence: EnvironmentPrecedence::AfterFilesBeforeCli,
                    deprecation: variable.deprecation,
                    security_relevant: field.security_relevant,
                })
        })
        .collect::<Vec<_>>();
    metadata.extend([
        EnvironmentVariableMetadata {
            name: super::acp::MAX_ITERATIONS_ENV_VAR.to_string(),
            config_field: "acp.max_iterations".to_string(),
            parser: EnvironmentValueParser::NonZeroU32,
            secrecy: EnvironmentSecrecy::Public,
            precedence: EnvironmentPrecedence::AfterFilesBeforeCli,
            deprecation: EnvironmentDeprecation::Current,
            security_relevant: true,
        },
        EnvironmentVariableMetadata {
            name: super::acp::LEGACY_MAX_ITERATIONS_ENV_VAR.to_string(),
            config_field: "acp.max_iterations".to_string(),
            parser: EnvironmentValueParser::NonZeroU32,
            secrecy: EnvironmentSecrecy::Public,
            precedence: EnvironmentPrecedence::AfterFilesBeforeCli,
            deprecation: EnvironmentDeprecation::Deprecated {
                replacement: super::acp::MAX_ITERATIONS_ENV_VAR.to_string(),
            },
            security_relevant: true,
        },
    ]);
    metadata.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    metadata
}

#[derive(Clone)]
enum ParsedValue {
    Boolean(bool),
    U16(u16),
    U32(u32),
    U64(u64),
    Usize(usize),
    NonZeroU32(NonZeroU32),
    F32(f32),
    String(String),
    ApiKey(ApiKey),
    SensitiveHeaders {
        value: SensitiveHeaders,
        source: serde_json::Value,
    },
    Json(serde_json::Value),
}

struct EnvironmentValueOrigin(String);

impl ParsedValue {
    fn to_config_value(&self, origin: &EnvironmentValueOrigin) -> Result<config::Value, String> {
        let value = match self {
            Self::Boolean(value) => config::Value::new(Some(&origin.0), *value),
            Self::U16(value) => config::Value::new(Some(&origin.0), *value),
            Self::U32(value) => config::Value::new(Some(&origin.0), *value),
            Self::U64(value) => config::Value::new(Some(&origin.0), *value),
            Self::Usize(value) => config::Value::new(
                Some(&origin.0),
                u64::try_from(*value).map_err(|error| {
                    format!("platform-sized integer conversion failed: {error}")
                })?,
            ),
            Self::NonZeroU32(value) => config::Value::new(Some(&origin.0), value.get()),
            Self::F32(value) => config::Value::new(Some(&origin.0), f64::from(*value)),
            Self::String(value) => config::Value::new(Some(&origin.0), value.clone()),
            Self::ApiKey(value) => {
                config::Value::new(Some(&origin.0), value.expose(ToString::to_string))
            }
            Self::SensitiveHeaders { value, source } => {
                let _validated_header_count = value.len();
                json_to_config_value(source, origin)?
            }
            Self::Json(source) => json_to_config_value(source, origin)?,
        };
        Ok(value)
    }
}

fn json_to_config_value(
    value: &serde_json::Value,
    origin: &EnvironmentValueOrigin,
) -> Result<config::Value, String> {
    let kind = match value {
        serde_json::Value::Null => config::ValueKind::Nil,
        serde_json::Value::Bool(value) => config::ValueKind::Boolean(*value),
        serde_json::Value::Number(value) => {
            if let Some(value) = value.as_u64() {
                config::ValueKind::U64(value)
            } else if let Some(value) = value.as_i64() {
                config::ValueKind::I64(value)
            } else if let Some(value) = value.as_f64() {
                config::ValueKind::Float(value)
            } else {
                return Err("JSON number is not representable as u64, i64, or f64".to_string());
            }
        }
        serde_json::Value::String(value) => config::ValueKind::String(value.clone()),
        serde_json::Value::Array(values) => config::ValueKind::Array(
            values
                .iter()
                .map(|value| json_to_config_value(value, origin))
                .collect::<Result<Vec<_>, _>>()?,
        ),
        serde_json::Value::Object(values) => config::ValueKind::Table(
            values
                .iter()
                .map(|(key, value)| {
                    json_to_config_value(value, origin).map(|value| (key.clone(), value))
                })
                .collect::<Result<config::Map<_, _>, _>>()?,
        ),
    };
    Ok(config::Value::new(Some(&origin.0), kind))
}

struct PendingValue {
    field: RegisteredField,
    variable: RegisteredVariable,
    raw: String,
}

#[derive(Clone)]
struct EnvironmentOverride {
    field: RegisteredField,
    variable: RegisteredVariable,
    value: ParsedValue,
}

/// Replace exact fields in the untyped merged configuration with values from
/// the process environment. Applying values before deserialization lets a
/// valid higher-precedence environment value replace an invalid lower file
/// value. Direct replacement, rather than `config`'s deep table merge, also
/// gives collection-valued fields ordinary whole-field precedence.
pub(super) fn apply_process_environment(
    config: &mut config::Config,
) -> Result<(), EnvironmentConfigError> {
    apply_environment_to_config(config, std::env::vars_os())
}

fn apply_environment_to_config(
    config: &mut config::Config,
    values: impl IntoIterator<Item = (OsString, OsString)>,
) -> Result<(), EnvironmentConfigError> {
    for environment_override in collect_environment(values)? {
        let origin = EnvironmentValueOrigin(format!(
            "environment variable {}",
            environment_override.variable.name
        ));
        let config_value = environment_override
            .value
            .to_config_value(&origin)
            .map_err(|reason| EnvironmentConfigError::InvalidValue {
                name: environment_override.variable.name.clone(),
                config_field: environment_override.field.config_field.clone(),
                expected: parser_expectation(environment_override.field.parser),
                reason,
            })?;
        set_exact_config_value(
            &mut config.cache,
            &environment_override.field.config_field,
            config_value,
        )?;
    }
    Ok(())
}

fn set_exact_config_value(
    root: &mut config::Value,
    config_field: &str,
    value: config::Value,
) -> Result<(), EnvironmentConfigError> {
    let invalid = |reason: String| EnvironmentConfigError::InvalidRegistryPath {
        config_field: config_field.to_string(),
        reason,
    };
    let mut segments = config_field.split('.').peekable();
    let mut current = root;
    while let Some(segment) = segments.next() {
        if segment.is_empty() {
            return Err(invalid("path contains an empty segment".to_string()));
        }
        if !matches!(current.kind, config::ValueKind::Table(_)) {
            current.kind = config::ValueKind::Table(config::Map::new());
        }
        let config::ValueKind::Table(table) = &mut current.kind else {
            return Err(invalid(
                "path traversal did not produce a table".to_string(),
            ));
        };
        if segments.peek().is_none() {
            table.insert(segment.to_string(), value);
            return Ok(());
        }
        current = table.entry(segment.to_string()).or_insert_with(|| {
            config::Value::new(None, config::Map::<String, config::Value>::new())
        });
    }
    Err(invalid("path contains no segments".to_string()))
}

#[cfg(test)]
fn apply_environment(
    config: &mut AppConfig,
    values: impl IntoIterator<Item = (OsString, OsString)>,
) -> Result<(), EnvironmentConfigError> {
    for environment_override in collect_environment(values)? {
        apply_value(
            config,
            &environment_override.field,
            &environment_override.variable.name,
            environment_override.value,
        )?;
    }
    Ok(())
}

fn collect_environment(
    values: impl IntoIterator<Item = (OsString, OsString)>,
) -> Result<Vec<EnvironmentOverride>, EnvironmentConfigError> {
    let registry = registry();
    let mut by_name = HashMap::new();
    for field in &registry {
        for variable in &field.variables {
            if let Some((prior_field, _)) =
                by_name.insert(variable.name.as_str(), (field, variable))
            {
                return Err(EnvironmentConfigError::DuplicateRegistration {
                    name: variable.name.clone(),
                    first_field: prior_field.config_field.clone(),
                    second_field: field.config_field.clone(),
                });
            }
        }
    }

    let mut environment = Vec::with_capacity(by_name.len());
    let mut first_unknown = None::<String>;
    for (name, value) in values {
        let Some(name_text) = name.to_str() else {
            if is_openclaudia_name(&name) {
                return Err(EnvironmentConfigError::NonUnicodeName);
            }
            continue;
        };
        if by_name.contains_key(name_text) {
            environment.push((name, value));
        } else if name_text.starts_with("OPENCLAUDIA_")
            && !is_external_openclaudia_variable(name_text)
        {
            let unknown = name_text.to_string();
            if first_unknown
                .as_ref()
                .is_none_or(|current| unknown.as_str() < current.as_str())
            {
                first_unknown = Some(unknown);
            }
        }
    }
    if let Some(name) = first_unknown {
        return Err(EnvironmentConfigError::UnknownVariable { name });
    }
    environment.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    let mut pending = BTreeMap::<ConfigField, Vec<PendingValue>>::new();

    for (name, value) in environment {
        let Some(name_text) = name.to_str() else {
            return Err(EnvironmentConfigError::NonUnicodeName);
        };
        if let Some((field, variable)) = by_name.get(name_text) {
            let raw = value
                .into_string()
                .map_err(|_| EnvironmentConfigError::NonUnicodeValue {
                    name: name_text.to_string(),
                })?;
            if raw.len() > MAX_ENVIRONMENT_VALUE_BYTES {
                return Err(EnvironmentConfigError::ValueTooLong {
                    name: name_text.to_string(),
                    max_bytes: MAX_ENVIRONMENT_VALUE_BYTES,
                });
            }
            // Preserve the historical "empty means unset" behavior only for
            // presentation-only values. Empty authority, boundary, budget,
            // path, and secret settings are malformed and must fail visibly.
            if raw.is_empty() && !field.security_relevant {
                continue;
            }
            pending.entry(field.field).or_default().push(PendingValue {
                field: (*field).clone(),
                variable: (*variable).clone(),
                raw,
            });
        }
    }

    resolve_pending_values(pending)
}

fn resolve_pending_values(
    pending: BTreeMap<ConfigField, Vec<PendingValue>>,
) -> Result<Vec<EnvironmentOverride>, EnvironmentConfigError> {
    let mut overrides = Vec::with_capacity(pending.len());
    for (_, mut candidates) in pending {
        if candidates.len() != 1 {
            candidates.sort_unstable_by(|left, right| left.variable.name.cmp(&right.variable.name));
            return Err(EnvironmentConfigError::AmbiguousField {
                config_field: candidates[0].field.config_field.clone(),
                names: candidates
                    .into_iter()
                    .map(|candidate| candidate.variable.name)
                    .collect(),
            });
        }
        let Some(candidate) = candidates.pop() else {
            return Err(EnvironmentConfigError::InvalidRegistryPath {
                config_field: "<unknown>".to_string(),
                reason: "environment candidate set was unexpectedly empty".to_string(),
            });
        };
        if let EnvironmentDeprecation::Deprecated { replacement } = &candidate.variable.deprecation
        {
            tracing::warn!(
                variable = %candidate.variable.name,
                replacement = %replacement,
                "deprecated OpenClaudia environment variable spelling"
            );
        }
        let parsed = parse_value(&candidate.field, &candidate.variable.name, candidate.raw)?;
        overrides.push(EnvironmentOverride {
            field: candidate.field,
            variable: candidate.variable,
            value: parsed,
        });
    }
    Ok(overrides)
}

#[allow(clippy::too_many_lines)] // exhaustive dispatch for the finite parser schema
fn parse_value(
    field: &RegisteredField,
    name: &str,
    raw: String,
) -> Result<ParsedValue, EnvironmentConfigError> {
    let invalid = |expected: &'static str, reason: String| EnvironmentConfigError::InvalidValue {
        name: name.to_string(),
        config_field: field.config_field.clone(),
        expected,
        reason,
    };
    match field.parser {
        EnvironmentValueParser::Boolean => match raw.as_str() {
            "true" => Ok(ParsedValue::Boolean(true)),
            "false" => Ok(ParsedValue::Boolean(false)),
            _ => Err(invalid(
                "`true` or `false`",
                "unsupported boolean spelling".to_string(),
            )),
        },
        EnvironmentValueParser::U16 => raw
            .parse::<u16>()
            .map(ParsedValue::U16)
            .map_err(|error| invalid("an unsigned 16-bit integer", error.to_string())),
        EnvironmentValueParser::U32 => raw
            .parse::<u32>()
            .map(ParsedValue::U32)
            .map_err(|error| invalid("an unsigned 32-bit integer", error.to_string())),
        EnvironmentValueParser::U64 => raw
            .parse::<u64>()
            .map(ParsedValue::U64)
            .map_err(|error| invalid("an unsigned 64-bit integer", error.to_string())),
        EnvironmentValueParser::Usize => raw
            .parse::<usize>()
            .map(ParsedValue::Usize)
            .map_err(|error| invalid("a non-negative platform-sized integer", error.to_string())),
        EnvironmentValueParser::NonZeroU32 => raw
            .parse::<u32>()
            .map_err(|error| invalid("a non-zero unsigned 32-bit integer", error.to_string()))
            .and_then(|value| {
                NonZeroU32::new(value)
                    .map(ParsedValue::NonZeroU32)
                    .ok_or_else(|| {
                        invalid(
                            "a non-zero unsigned 32-bit integer",
                            "zero is not allowed".to_string(),
                        )
                    })
            }),
        EnvironmentValueParser::F32 => raw
            .parse::<f32>()
            .map_err(|error| invalid("a finite 32-bit floating-point number", error.to_string()))
            .and_then(|value| {
                if value.is_finite() {
                    Ok(ParsedValue::F32(value))
                } else {
                    Err(invalid(
                        "a finite 32-bit floating-point number",
                        "non-finite values are not allowed".to_string(),
                    ))
                }
            }),
        EnvironmentValueParser::String => {
            if raw.is_empty() {
                Err(invalid(
                    "a non-empty UTF-8 string",
                    "empty values are not allowed".to_string(),
                ))
            } else {
                Ok(ParsedValue::String(raw))
            }
        }
        EnvironmentValueParser::VddMode => match raw.as_str() {
            "advisory" | "blocking" => Ok(ParsedValue::String(raw)),
            _ => Err(invalid(
                parser_expectation(field.parser),
                "unsupported VDD mode".to_string(),
            )),
        },
        EnvironmentValueParser::GuardrailMode => match raw.as_str() {
            "strict" | "advisory" => Ok(ParsedValue::String(raw)),
            _ => Err(invalid(
                parser_expectation(field.parser),
                "unsupported guardrail mode".to_string(),
            )),
        },
        EnvironmentValueParser::GuardrailAction => match raw.as_str() {
            "warn" | "block" | "inject_findings" => Ok(ParsedValue::String(raw)),
            _ => Err(invalid(
                parser_expectation(field.parser),
                "unsupported guardrail action".to_string(),
            )),
        },
        EnvironmentValueParser::RunAfter => match raw.as_str() {
            "every_edit" | "every_turn" | "on_commit" => Ok(ParsedValue::String(raw)),
            _ => Err(invalid(
                parser_expectation(field.parser),
                "unsupported quality-gate schedule".to_string(),
            )),
        },
        EnvironmentValueParser::ReasoningEffort => match raw.as_str() {
            "none" | "minimal" | "low" | "medium" | "med" | "high" | "xhigh" | "max" => {
                Ok(ParsedValue::String(raw))
            }
            _ => Err(invalid(
                parser_expectation(field.parser),
                "unsupported provider reasoning effort".to_string(),
            )),
        },
        EnvironmentValueParser::ApiKey => ApiKey::try_from_string(raw)
            .map(ParsedValue::ApiKey)
            .map_err(|error| invalid("a valid provider API key", error.to_string())),
        EnvironmentValueParser::JsonSensitiveHeaders => {
            let source: serde_json::Value = serde_json::from_str(&raw)
                .map_err(|error| invalid(parser_expectation(field.parser), error.to_string()))?;
            let value = serde_json::from_value(source.clone())
                .map_err(|error| invalid(parser_expectation(field.parser), error.to_string()))?;
            Ok(ParsedValue::SensitiveHeaders { value, source })
        }
        EnvironmentValueParser::JsonStringList
        | EnvironmentValueParser::JsonStringListMap
        | EnvironmentValueParser::JsonQualityChecks
        | EnvironmentValueParser::JsonToolCaps
        | EnvironmentValueParser::JsonStringSet => serde_json::from_str(&raw)
            .map(ParsedValue::Json)
            .map_err(|error| invalid(parser_expectation(field.parser), error.to_string())),
    }
}

const fn parser_expectation(parser: EnvironmentValueParser) -> &'static str {
    match parser {
        EnvironmentValueParser::VddMode => "`advisory` or `blocking`",
        EnvironmentValueParser::GuardrailMode => "`strict` or `advisory`",
        EnvironmentValueParser::GuardrailAction => "`warn`, `block`, or `inject_findings`",
        EnvironmentValueParser::RunAfter => "`every_edit`, `every_turn`, or `on_commit`",
        EnvironmentValueParser::ReasoningEffort => "a supported provider reasoning-effort level",
        EnvironmentValueParser::JsonStringList => "a JSON array of strings",
        EnvironmentValueParser::JsonStringListMap => {
            "a JSON object whose values are arrays of strings"
        }
        EnvironmentValueParser::JsonQualityChecks => "a JSON array of quality-check objects",
        EnvironmentValueParser::JsonToolCaps => {
            "a JSON object mapping tool names to non-negative integer caps"
        }
        EnvironmentValueParser::JsonStringSet => "a JSON array of unique strings",
        EnvironmentValueParser::JsonSensitiveHeaders => {
            "a JSON object mapping header names to secret string values"
        }
        _ => "the declared environment value type",
    }
}

#[cfg(test)]
#[allow(clippy::too_many_lines)] // exhaustive typed-field assertion target
fn apply_value(
    config: &mut AppConfig,
    definition: &RegisteredField,
    name: &str,
    value: ParsedValue,
) -> Result<(), EnvironmentConfigError> {
    macro_rules! expect_value {
        ($variant:ident) => {
            match value {
                ParsedValue::$variant(value) => value,
                _ => unreachable!("parser and field registry disagree"),
            }
        };
    }
    let invalid = |expected: &'static str, reason: String| EnvironmentConfigError::InvalidValue {
        name: name.to_string(),
        config_field: definition.config_field.clone(),
        expected,
        reason,
    };
    match definition.field {
        ConfigField::ProxyPort => config.proxy.port = expect_value!(U16),
        ConfigField::ProxyHost => config.proxy.host = expect_value!(String),
        ConfigField::ProxyTarget => config.proxy.target = expect_value!(String),
        ConfigField::ProxyMaxResponseBytes => {
            config.proxy.max_response_bytes = expect_value!(Usize);
        }
        ConfigField::Provider {
            name: provider_name,
            field,
        } => {
            let provider = config.providers.get_mut(provider_name).ok_or_else(|| {
                EnvironmentConfigError::MissingProvider {
                    name: name.to_string(),
                    provider: provider_name.to_string(),
                }
            })?;
            match field {
                ProviderField::ApiKey => provider.api_key = Some(expect_value!(ApiKey)),
                ProviderField::BaseUrl => provider.base_url = expect_value!(String),
                ProviderField::Model => provider.model = Some(expect_value!(String)),
                ProviderField::Headers => {
                    let ParsedValue::SensitiveHeaders { value, .. } = value else {
                        unreachable!("parser and field registry disagree");
                    };
                    provider.headers = value;
                }
                ProviderField::ThinkingEnabled => {
                    provider.thinking.enabled = expect_value!(Boolean);
                }
                ProviderField::ThinkingBudgetTokens => {
                    provider.thinking.budget_tokens = Some(expect_value!(U32));
                }
                ProviderField::ThinkingPreserveAcrossTurns => {
                    provider.thinking.preserve_across_turns = expect_value!(Boolean);
                }
                ProviderField::ThinkingReasoningEffort => {
                    provider.thinking.reasoning_effort = Some(expect_value!(String));
                }
                ProviderField::ThinkingAdaptive => {
                    provider.thinking.adaptive = expect_value!(Boolean);
                }
            }
        }
        ConfigField::SessionTimeoutMinutes => config.session.timeout_minutes = expect_value!(U64),
        ConfigField::SessionPersistPath => {
            config.session.persist_path = expect_value!(String).into();
        }
        ConfigField::SessionMaxTurns => config.session.max_turns = expect_value!(U32),
        ConfigField::SessionTokenTrackingEnabled => {
            config.session.token_tracking.enabled = expect_value!(Boolean);
        }
        ConfigField::SessionTokenTrackingLogUsage => {
            config.session.token_tracking.log_usage = expect_value!(Boolean);
        }
        ConfigField::SessionTokenTrackingWarnThreshold => {
            config.session.token_tracking.warn_threshold = expect_value!(F32);
        }
        ConfigField::SessionTokenTrackingMaxOutputTokens => {
            config.session.token_tracking.max_output_tokens = expect_value!(U32);
        }
        ConfigField::VddEnabled => config.vdd.enabled = expect_value!(Boolean),
        ConfigField::VddMode => {
            config.vdd.mode = match expect_value!(String).as_str() {
                "advisory" => VddMode::Advisory,
                "blocking" => VddMode::Blocking,
                other => {
                    return Err(invalid(
                        "`advisory` or `blocking`",
                        format!("unsupported VDD mode {other:?}"),
                    ))
                }
            };
        }
        ConfigField::VddAdversaryProvider => config.vdd.adversary.provider = expect_value!(String),
        ConfigField::VddAdversaryModel => config.vdd.adversary.model = Some(expect_value!(String)),
        ConfigField::VddAdversaryApiKey => {
            config.vdd.adversary.api_key = Some(expect_value!(ApiKey));
        }
        ConfigField::VddAdversaryTemperature => {
            config.vdd.adversary.temperature = expect_value!(F32);
        }
        ConfigField::VddAdversaryMaxTokens => config.vdd.adversary.max_tokens = expect_value!(U32),
        ConfigField::VddAdversaryRequestTimeoutSeconds => {
            config.vdd.adversary.request_timeout_seconds = expect_value!(U64);
        }
        ConfigField::VddThresholdsMaxIterations => {
            config.vdd.thresholds.max_iterations = expect_value!(U32);
        }
        ConfigField::VddThresholdsFalsePositiveRate => {
            config.vdd.thresholds.false_positive_rate = expect_value!(F32);
        }
        ConfigField::VddThresholdsMinIterations => {
            config.vdd.thresholds.min_iterations = expect_value!(U32);
        }
        ConfigField::VddStaticAnalysisEnabled => {
            config.vdd.static_analysis.enabled = expect_value!(Boolean);
        }
        ConfigField::VddStaticAnalysisAutoDetect => {
            config.vdd.static_analysis.auto_detect = expect_value!(Boolean);
        }
        ConfigField::VddStaticAnalysisCommands => {
            config.vdd.static_analysis.commands = serde_json::from_value(expect_value!(Json))
                .map_err(|error| {
                    invalid(
                        parser_expectation(EnvironmentValueParser::JsonStringList),
                        error.to_string(),
                    )
                })?;
        }
        ConfigField::VddStaticAnalysisTimeoutSeconds => {
            config.vdd.static_analysis.timeout_seconds = expect_value!(U64);
        }
        ConfigField::VddTrackingPersist => config.vdd.tracking.persist = expect_value!(Boolean),
        ConfigField::VddTrackingPath => config.vdd.tracking.path = expect_value!(String).into(),
        ConfigField::VddTrackingLogAdversaryResponses => {
            config.vdd.tracking.log_adversary_responses = expect_value!(Boolean);
        }
        ConfigField::GuardrailsBlastRadiusEnabled => {
            blast_radius(config).enabled = expect_value!(Boolean);
        }
        ConfigField::GuardrailsBlastRadiusMode => {
            blast_radius(config).mode = parse_guardrail_mode(&expect_value!(String), &invalid)?;
        }
        ConfigField::GuardrailsBlastRadiusAllowedPaths => {
            blast_radius(config).allowed_paths = json_value(
                expect_value!(Json),
                EnvironmentValueParser::JsonStringList,
                &invalid,
            )?;
        }
        ConfigField::GuardrailsBlastRadiusDeniedPaths => {
            blast_radius(config).denied_paths = json_value(
                expect_value!(Json),
                EnvironmentValueParser::JsonStringList,
                &invalid,
            )?;
        }
        ConfigField::GuardrailsBlastRadiusMaxFilesPerRun => {
            blast_radius(config).max_files_per_run = Some(expect_value!(NonZeroU32));
        }
        ConfigField::GuardrailsBlastRadiusMaxLinesPerRun => {
            blast_radius(config).max_lines_per_run = Some(expect_value!(NonZeroU32));
        }
        ConfigField::GuardrailsBlastRadiusMaxToolCallsPerRun => {
            blast_radius(config).max_tool_calls_per_run = Some(expect_value!(NonZeroU32));
        }
        ConfigField::GuardrailsBlastRadiusMaxMutationsPerRun => {
            blast_radius(config).max_mutations_per_run = Some(expect_value!(NonZeroU32));
        }
        ConfigField::GuardrailsDiffMonitorEnabled => {
            diff_monitor(config).enabled = expect_value!(Boolean);
        }
        ConfigField::GuardrailsDiffMonitorMaxLinesChanged => {
            diff_monitor(config).max_lines_changed = expect_value!(U32);
        }
        ConfigField::GuardrailsDiffMonitorMaxFilesChanged => {
            diff_monitor(config).max_files_changed = expect_value!(U32);
        }
        ConfigField::GuardrailsDiffMonitorAction => {
            diff_monitor(config).action = parse_guardrail_action(&expect_value!(String), &invalid)?;
        }
        ConfigField::GuardrailsQualityGatesEnabled => {
            quality_gates(config).enabled = expect_value!(Boolean);
        }
        ConfigField::GuardrailsQualityGatesRunAfter => {
            quality_gates(config).run_after = parse_run_after(&expect_value!(String), &invalid)?;
        }
        ConfigField::GuardrailsQualityGatesFailAction => {
            quality_gates(config).fail_action =
                parse_guardrail_action(&expect_value!(String), &invalid)?;
        }
        ConfigField::GuardrailsQualityGatesChecks => {
            quality_gates(config).checks = json_value(
                expect_value!(Json),
                EnvironmentValueParser::JsonQualityChecks,
                &invalid,
            )?;
        }
        ConfigField::GuardrailsQualityGatesTimeoutSeconds => {
            quality_gates(config).timeout_seconds = expect_value!(U64);
        }
        ConfigField::PermissionsEnabled => config.permissions.enabled = expect_value!(Boolean),
        ConfigField::PermissionsDefaultAllow => {
            config.permissions.default_allow = json_value(
                expect_value!(Json),
                EnvironmentValueParser::JsonStringList,
                &invalid,
            )?;
        }
        ConfigField::PermissionsMcp => {
            config.permissions.mcp = json_value(
                expect_value!(Json),
                EnvironmentValueParser::JsonStringListMap,
                &invalid,
            )?;
        }
        ConfigField::MemoryAutomaticLearningEnabled => {
            config.memory.automatic_learning_enabled = expect_value!(Boolean);
        }
        ConfigField::MemoryTeamId => {
            config.memory.team_id = Some(expect_value!(String).parse().map_err(
                |error: crate::team_memory::TeamAuthorityError| {
                    invalid(
                        "a strict team-<32 lowercase hex> identity",
                        error.to_string(),
                    )
                },
            )?);
        }
        ConfigField::MemoryTeamMemoryPath => {
            config.memory.team_memory_path = Some(expect_value!(String).into());
        }
        ConfigField::WebFetchDistillationEnabled => {
            config.web_fetch.distillation_enabled = expect_value!(Boolean);
        }
        ConfigField::WebFetchMaxDistillationBytes => {
            config.web_fetch.max_distillation_bytes = expect_value!(Usize);
        }
        ConfigField::WebFetchDistillationProvider => {
            config.web_fetch.distillation_provider = Some(expect_value!(String));
        }
        ConfigField::WebFetchDistillationModel => {
            config.web_fetch.distillation_model = Some(expect_value!(String));
        }
        ConfigField::WebFetchPreapprovedDomains => {
            config.web_fetch.preapproved_domains = json_value(
                expect_value!(Json),
                EnvironmentValueParser::JsonStringList,
                &invalid,
            )?;
        }
        ConfigField::WebFetchExactPrivateOrigins => {
            config.web_fetch.exact_private_origins = json_value(
                expect_value!(Json),
                EnvironmentValueParser::JsonStringList,
                &invalid,
            )?;
        }
        ConfigField::PolicyMaxRequestTokens => {
            config.policy.max_request_tokens = Some(expect_value!(Usize));
        }
        ConfigField::PolicyMaxSessionTokens => {
            config.policy.max_session_tokens = Some(expect_value!(Usize));
        }
        ConfigField::PolicyToolCaps => {
            config.policy.tool_caps = json_value(
                expect_value!(Json),
                EnvironmentValueParser::JsonToolCaps,
                &invalid,
            )?;
        }
        ConfigField::PolicyModelAllowlist => {
            config.policy.model_allowlist = json_value(
                expect_value!(Json),
                EnvironmentValueParser::JsonStringSet,
                &invalid,
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
fn json_value<T: serde::de::DeserializeOwned>(
    value: serde_json::Value,
    parser: EnvironmentValueParser,
    invalid: &impl Fn(&'static str, String) -> EnvironmentConfigError,
) -> Result<T, EnvironmentConfigError> {
    serde_json::from_value(value)
        .map_err(|error| invalid(parser_expectation(parser), error.to_string()))
}

#[cfg(test)]
fn blast_radius(config: &mut AppConfig) -> &mut BlastRadiusConfig {
    config
        .guardrails
        .blast_radius
        .get_or_insert_with(BlastRadiusConfig::default)
}

#[cfg(test)]
fn diff_monitor(config: &mut AppConfig) -> &mut DiffMonitorConfig {
    config
        .guardrails
        .diff_monitor
        .get_or_insert_with(DiffMonitorConfig::default)
}

#[cfg(test)]
fn quality_gates(config: &mut AppConfig) -> &mut QualityGatesConfig {
    config
        .guardrails
        .quality_gates
        .get_or_insert_with(QualityGatesConfig::default)
}

#[cfg(test)]
fn parse_guardrail_mode(
    raw: &str,
    invalid: &impl Fn(&'static str, String) -> EnvironmentConfigError,
) -> Result<GuardrailMode, EnvironmentConfigError> {
    match raw {
        "strict" => Ok(GuardrailMode::Strict),
        "advisory" => Ok(GuardrailMode::Advisory),
        _ => Err(invalid(
            "`strict` or `advisory`",
            "unsupported guardrail mode".to_string(),
        )),
    }
}

#[cfg(test)]
fn parse_guardrail_action(
    raw: &str,
    invalid: &impl Fn(&'static str, String) -> EnvironmentConfigError,
) -> Result<GuardrailAction, EnvironmentConfigError> {
    match raw {
        "warn" => Ok(GuardrailAction::Warn),
        "block" => Ok(GuardrailAction::Block),
        "inject_findings" => Ok(GuardrailAction::InjectFindings),
        _ => Err(invalid(
            "`warn`, `block`, or `inject_findings`",
            "unsupported guardrail action".to_string(),
        )),
    }
}

#[cfg(test)]
fn parse_run_after(
    raw: &str,
    invalid: &impl Fn(&'static str, String) -> EnvironmentConfigError,
) -> Result<RunAfter, EnvironmentConfigError> {
    match raw {
        "every_edit" => Ok(RunAfter::EveryEdit),
        "every_turn" => Ok(RunAfter::EveryTurn),
        "on_commit" => Ok(RunAfter::OnCommit),
        _ => Err(invalid(
            "`every_edit`, `every_turn`, or `on_commit`",
            "unsupported quality-gate schedule".to_string(),
        )),
    }
}

fn is_openclaudia_name(name: &OsStr) -> bool {
    name.to_string_lossy().starts_with("OPENCLAUDIA_")
}

fn is_external_openclaudia_variable(name: &str) -> bool {
    name.starts_with("OPENCLAUDIA_TEST_")
        || name == crate::claude_credentials::EXPERIMENTAL_DIRECT_SUBSCRIPTION_ENV
        || matches!(
            name,
            "OPENCLAUDIA_ACP__MAX_ITERATIONS"
                | "OPENCLAUDIA_ACP_MAX_ITERATIONS"
                | "OPENCLAUDIA_AGENT_ENV_GRANTS"
                | "OPENCLAUDIA_AGENT_NETWORK"
                | "OPENCLAUDIA_AGENT_READ_ONLY_ROOTS"
                | "OPENCLAUDIA_AGENT_READ_WRITE_ROOTS"
                | "OPENCLAUDIA_ALLOW_OUT_OF_ROOT"
                | "OPENCLAUDIA_BASH_SANDBOX"
                | "OPENCLAUDIA_DISABLE_POLICY_SKILLS"
                | "OPENCLAUDIA_DUMP_TOOLS_PATH"
                | "OPENCLAUDIA_HOOK_APPROVALS_PATH"
                | "OPENCLAUDIA_LSP_MAX_MESSAGES"
                | "OPENCLAUDIA_MANAGED_PATH"
                | "OPENCLAUDIA_MCP_ENV_GRANTS"
                | "OPENCLAUDIA_PROJECT_SECRET_MASKS"
                | "OPENCLAUDIA_S031_CRASH_MODE"
                | "OPENCLAUDIA_S031_CRASH_ROOT"
                | "OPENCLAUDIA_SANDBOX"
                | "OPENCLAUDIA_TRUST_MCP_SERVERS"
                | "OPENCLAUDIA_TRUST_UNSANDBOXED_HOOKS"
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    use crate::config::{
        GuardrailsConfig, HooksConfig, KeybindingsConfig, MemoryConfig, PermissionsConfig,
        ProxyConfig, SessionConfig, VddConfig, WebFetchConfig,
    };

    fn app_config() -> AppConfig {
        let providers = PROVIDERS
            .iter()
            .map(|provider| {
                (
                    provider.config_name.to_string(),
                    crate::config::ProviderConfig {
                        api_key: None,
                        base_url: if matches!(
                            provider.config_name,
                            "ollama" | "local" | "lmstudio" | "localai" | "text-generation-webui"
                        ) {
                            "http://localhost:1234/v1".to_string()
                        } else {
                            "https://example.com/v1".to_string()
                        },
                        model: None,
                        headers: SensitiveHeaders::new(),
                        thinking: crate::config::ThinkingConfig::default(),
                    },
                )
            })
            .collect();
        AppConfig {
            proxy: ProxyConfig::default(),
            providers,
            hooks: HooksConfig::default(),
            session: SessionConfig::default(),
            keybindings: KeybindingsConfig::default(),
            vdd: VddConfig::default(),
            guardrails: GuardrailsConfig::default(),
            permissions: PermissionsConfig::default(),
            memory: MemoryConfig::default(),
            web_fetch: WebFetchConfig::default(),
            remote_actions: crate::config::RemoteActionsConfig::default(),
            policy: crate::services::policy::EnterprisePolicy::default(),
            managed_settings_path: None,
        }
    }

    #[test]
    fn multiword_and_provider_namespaces_reach_the_intended_typed_fields() {
        let mut config = app_config();
        apply_environment(
            &mut config,
            [
                ("OPENCLAUDIA_SESSION__PERSIST_PATH", "state/sessions"),
                (
                    "OPENCLAUDIA_VDD__TRACKING__LOG_ADVERSARY_RESPONSES",
                    "false",
                ),
                (
                    "OPENCLAUDIA_PROVIDERS__OPENAI_COMPATIBLE__BASE_URL",
                    "https://gateway.example/v1",
                ),
                (
                    "OPENCLAUDIA_PROVIDERS__ANTHROPIC__THINKING__BUDGET_TOKENS",
                    "8192",
                ),
            ]
            .into_iter()
            .map(|(name, value)| (OsString::from(name), OsString::from(value))),
        )
        .expect("typed environment must apply");

        assert_eq!(
            config.session.persist_path,
            std::path::Path::new("state/sessions")
        );
        assert!(!config.vdd.tracking.log_adversary_responses);
        assert_eq!(
            config.providers["openai-compatible"].base_url,
            "https://gateway.example/v1"
        );
        assert_eq!(
            config.providers["anthropic"].thinking.budget_tokens,
            Some(8192)
        );
    }

    #[test]
    fn exact_legacy_names_remain_typed_but_are_marked_deprecated() {
        let mut config = app_config();
        apply_environment(
            &mut config,
            [(
                OsString::from("OPENCLAUDIA_SESSION_PERSIST_PATH"),
                OsString::from("legacy/state"),
            )],
        )
        .expect("legacy exact name must remain compatible");
        assert_eq!(
            config.session.persist_path,
            std::path::Path::new("legacy/state")
        );

        let metadata = environment_variable_metadata();
        let legacy = metadata
            .iter()
            .find(|entry| entry.name == "OPENCLAUDIA_SESSION_PERSIST_PATH")
            .expect("legacy metadata");
        assert!(matches!(
            legacy.deprecation,
            EnvironmentDeprecation::Deprecated { .. }
        ));
    }

    #[test]
    fn unknown_and_ambiguous_configuration_names_fail_closed() {
        let mut config = app_config();
        let unknown = apply_environment(
            &mut config,
            [(
                OsString::from("OPENCLAUDIA_PERMISSIONS_ENABELD"),
                OsString::from("false"),
            )],
        )
        .expect_err("unknown security setting must fail");
        assert!(matches!(
            unknown,
            EnvironmentConfigError::UnknownVariable { .. }
        ));

        let ambiguous = apply_environment(
            &mut config,
            [
                (
                    OsString::from("OPENCLAUDIA_PROXY__PORT"),
                    OsString::from("9000"),
                ),
                (
                    OsString::from("OPENCLAUDIA_PROXY_PORT"),
                    OsString::from("9001"),
                ),
            ],
        )
        .expect_err("two names for one field must fail");
        assert!(matches!(
            ambiguous,
            EnvironmentConfigError::AmbiguousField { .. }
        ));

        let provider_ambiguity = apply_environment(
            &mut config,
            [
                (
                    OsString::from("GOOGLE_API_KEY"),
                    OsString::from("secret-one"),
                ),
                (
                    OsString::from("GEMINI_API_KEY"),
                    OsString::from("secret-two"),
                ),
            ],
        )
        .expect_err("ecosystem aliases for one provider field must fail");
        let diagnostic = provider_ambiguity.to_string();
        assert!(diagnostic.contains("providers.google.api_key"));
        assert!(diagnostic.contains("GEMINI_API_KEY"));
        assert!(diagnostic.contains("GOOGLE_API_KEY"));
        assert!(!diagnostic.contains("secret-one"));
        assert!(!diagnostic.contains("secret-two"));
    }

    #[test]
    fn direct_subscription_acknowledgement_is_owned_outside_typed_config() {
        let mut config = app_config();
        apply_environment(
            &mut config,
            [(
                OsString::from(crate::claude_credentials::EXPERIMENTAL_DIRECT_SUBSCRIPTION_ENV),
                OsString::from(crate::claude_credentials::EXPERIMENTAL_DIRECT_SUBSCRIPTION_ACK),
            )],
        )
        .expect("experimental acknowledgement must reach its dedicated exact-value gate");
    }

    #[test]
    fn malformed_secret_fails_without_echoing_secret_bytes() {
        let mut config = app_config();
        let raw_secret = "secret\r\ninjected";
        let error = apply_environment(
            &mut config,
            [(
                OsString::from("OPENCLAUDIA_PROVIDERS__ANTHROPIC__API_KEY"),
                OsString::from(raw_secret),
            )],
        )
        .expect_err("control-bearing key must fail");
        let diagnostic = error.to_string();
        assert!(!diagnostic.contains(raw_secret));
        assert!(diagnostic.contains("OPENCLAUDIA_PROVIDERS__ANTHROPIC__API_KEY"));
    }

    #[test]
    fn every_security_relevant_canonical_name_rejects_an_empty_value() {
        for definition in registry()
            .into_iter()
            .filter(|definition| definition.security_relevant)
        {
            let canonical = definition
                .variables
                .iter()
                .find(|variable| variable.deprecation == EnvironmentDeprecation::Current)
                .expect("every field has one canonical name");
            let Err(error) =
                collect_environment([(OsString::from(&canonical.name), OsString::new())])
            else {
                panic!("empty security-relevant values must fail closed");
            };
            assert!(
                matches!(error, EnvironmentConfigError::InvalidValue { .. }),
                "{} ({}) returned the wrong failure: {error}",
                canonical.name,
                definition.config_field
            );
        }
    }

    #[test]
    fn empty_presentation_only_value_preserves_lower_precedence_state() {
        let mut config = app_config();
        config.session.token_tracking.log_usage = true;
        apply_environment(
            &mut config,
            [(
                OsString::from("OPENCLAUDIA_SESSION__TOKEN_TRACKING__LOG_USAGE"),
                OsString::new(),
            )],
        )
        .expect("empty presentation-only value remains unset");
        assert!(config.session.token_tracking.log_usage);
    }

    #[test]
    fn malformed_values_fail_in_the_declared_parser_or_typed_deserializer() {
        for (name, raw) in [
            ("OPENCLAUDIA_PROXY__PORT", "70000"),
            ("OPENCLAUDIA_SESSION__MAX_TURNS", "-1"),
            ("OPENCLAUDIA_SESSION__TIMEOUT_MINUTES", "-1"),
            ("OPENCLAUDIA_POLICY__MAX_REQUEST_TOKENS", "-1"),
            ("OPENCLAUDIA_VDD__ENABLED", "yes"),
            ("OPENCLAUDIA_SESSION__TOKEN_TRACKING__WARN_THRESHOLD", "NaN"),
            (
                "OPENCLAUDIA_GUARDRAILS__BLAST_RADIUS__MAX_FILES_PER_RUN",
                "0",
            ),
            ("OPENCLAUDIA_PERMISSIONS__DEFAULT_ALLOW", "{}"),
            ("OPENCLAUDIA_PERMISSIONS__MCP", "[]"),
            ("OPENCLAUDIA_GUARDRAILS__QUALITY_GATES__CHECKS", "{}"),
            ("OPENCLAUDIA_POLICY__TOOL_CAPS", "[]"),
            ("OPENCLAUDIA_POLICY__MODEL_ALLOWLIST", "{}"),
            ("OPENCLAUDIA_VDD__MODE", "enforcing"),
            ("OPENCLAUDIA_GUARDRAILS__BLAST_RADIUS__MODE", "enforcing"),
            ("OPENCLAUDIA_GUARDRAILS__DIFF_MONITOR__ACTION", "allow"),
            ("OPENCLAUDIA_GUARDRAILS__QUALITY_GATES__RUN_AFTER", "never"),
            (
                "OPENCLAUDIA_PROVIDERS__ANTHROPIC__THINKING__REASONING_EFFORT",
                "extreme",
            ),
            ("OPENCLAUDIA_PROVIDERS__ANTHROPIC__HEADERS", "[]"),
        ] {
            let builder = config::Config::builder().add_source(config::File::from_str(
                &baseline_yaml(),
                config::FileFormat::Yaml,
            ));
            let outcome = builder
                .build()
                .map_err(|error| EnvironmentConfigError::InvalidRegistryPath {
                    config_field: name.to_string(),
                    reason: error.to_string(),
                })
                .and_then(|mut merged| {
                    apply_environment_to_config(
                        &mut merged,
                        [(OsString::from(name), OsString::from(raw))],
                    )?;
                    merged
                        .try_deserialize::<AppConfig>()
                        .map(|_| ())
                        .map_err(|error| EnvironmentConfigError::InvalidValue {
                            name: name.to_string(),
                            config_field: "typed AppConfig".to_string(),
                            expected: "the declared typed field",
                            reason: error.to_string(),
                        })
                });
            assert!(outcome.is_err(), "{name}={raw:?} must be rejected");
        }
    }

    #[test]
    fn environment_values_are_bounded_before_parsing() {
        let oversized = "x".repeat(MAX_ENVIRONMENT_VALUE_BYTES + 1);
        let result = collect_environment([(
            OsString::from("OPENCLAUDIA_SESSION__PERSIST_PATH"),
            OsString::from(oversized),
        )]);
        let Err(error) = result else {
            panic!("oversized environment input must fail before parsing");
        };
        assert_eq!(
            error,
            EnvironmentConfigError::ValueTooLong {
                name: "OPENCLAUDIA_SESSION__PERSIST_PATH".to_string(),
                max_bytes: MAX_ENVIRONMENT_VALUE_BYTES,
            }
        );
    }

    #[test]
    fn metadata_is_unique_and_complete_for_registered_names() {
        let metadata = environment_variable_metadata();
        let unique = metadata
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<HashSet<_>>();
        assert_eq!(
            unique.len(),
            metadata.len(),
            "every exact name has one owner"
        );
        assert!(metadata.iter().all(|entry| {
            entry.precedence == EnvironmentPrecedence::AfterFilesBeforeCli
                && !entry.config_field.is_empty()
        }));
    }

    #[allow(clippy::too_many_lines)] // one non-default sample per registry field
    fn sample_for(field: ConfigField) -> &'static str {
        match field {
            ConfigField::VddMode => "blocking",
            ConfigField::GuardrailsBlastRadiusMode => "strict",
            ConfigField::GuardrailsDiffMonitorAction
            | ConfigField::GuardrailsQualityGatesFailAction => "block",
            ConfigField::GuardrailsQualityGatesRunAfter => "on_commit",
            ConfigField::VddStaticAnalysisCommands
            | ConfigField::GuardrailsBlastRadiusAllowedPaths
            | ConfigField::GuardrailsBlastRadiusDeniedPaths
            | ConfigField::PermissionsDefaultAllow
            | ConfigField::WebFetchPreapprovedDomains => "[\"typed-env-value\"]",
            ConfigField::WebFetchExactPrivateOrigins => "[\"http://127.0.0.1:8787\"]",
            ConfigField::GuardrailsQualityGatesChecks => {
                r#"[{"name":"typed-env","command":"true","required":false}]"#
            }
            ConfigField::PermissionsMcp => r#"{"typed-server":["typed-tool"]}"#,
            ConfigField::PolicyToolCaps => r#"{"typed-tool":7}"#,
            ConfigField::PolicyModelAllowlist => "[\"typed-model\"]",
            ConfigField::Provider {
                field: ProviderField::Headers,
                ..
            } => r#"{"x-typed-env":"secret-header-value"}"#,
            ConfigField::Provider {
                field: ProviderField::ApiKey,
                ..
            }
            | ConfigField::VddAdversaryApiKey => "typed-api-key-123",
            ConfigField::Provider {
                field: ProviderField::BaseUrl,
                ..
            } => "https://typed-env.example/v1",
            ConfigField::Provider {
                field: ProviderField::ThinkingReasoningEffort,
                ..
            } => "high",
            ConfigField::Provider {
                field: ProviderField::Model,
                ..
            }
            | ConfigField::ProxyHost
            | ConfigField::ProxyTarget
            | ConfigField::SessionPersistPath
            | ConfigField::VddAdversaryProvider
            | ConfigField::VddAdversaryModel
            | ConfigField::VddTrackingPath
            | ConfigField::WebFetchDistillationProvider
            | ConfigField::WebFetchDistillationModel
            | ConfigField::MemoryTeamMemoryPath => "typed-env-value",
            ConfigField::MemoryTeamId => "team-0123456789abcdef0123456789abcdef",
            ConfigField::SessionTokenTrackingWarnThreshold
            | ConfigField::VddAdversaryTemperature
            | ConfigField::VddThresholdsFalsePositiveRate => "0.25",
            ConfigField::ProxyPort => "9123",
            ConfigField::ProxyMaxResponseBytes
            | ConfigField::WebFetchMaxDistillationBytes
            | ConfigField::PolicyMaxRequestTokens
            | ConfigField::PolicyMaxSessionTokens => "7000",
            ConfigField::SessionTimeoutMinutes
            | ConfigField::VddAdversaryRequestTimeoutSeconds
            | ConfigField::VddStaticAnalysisTimeoutSeconds
            | ConfigField::GuardrailsQualityGatesTimeoutSeconds => "77",
            ConfigField::SessionMaxTurns
            | ConfigField::SessionTokenTrackingMaxOutputTokens
            | ConfigField::VddAdversaryMaxTokens
            | ConfigField::VddThresholdsMaxIterations
            | ConfigField::GuardrailsDiffMonitorMaxLinesChanged
            | ConfigField::GuardrailsDiffMonitorMaxFilesChanged
            | ConfigField::Provider {
                field: ProviderField::ThinkingBudgetTokens,
                ..
            }
            | ConfigField::GuardrailsBlastRadiusMaxFilesPerRun
            | ConfigField::GuardrailsBlastRadiusMaxLinesPerRun
            | ConfigField::GuardrailsBlastRadiusMaxToolCallsPerRun
            | ConfigField::GuardrailsBlastRadiusMaxMutationsPerRun => "7",
            ConfigField::VddThresholdsMinIterations => "1",
            ConfigField::MemoryAutomaticLearningEnabled
            | ConfigField::VddEnabled
            | ConfigField::GuardrailsBlastRadiusEnabled
            | ConfigField::GuardrailsDiffMonitorEnabled
            | ConfigField::GuardrailsQualityGatesEnabled
            | ConfigField::WebFetchDistillationEnabled
            | ConfigField::Provider {
                field: ProviderField::ThinkingPreserveAcrossTurns,
                ..
            } => "true",
            ConfigField::SessionTokenTrackingEnabled
            | ConfigField::SessionTokenTrackingLogUsage
            | ConfigField::VddStaticAnalysisEnabled
            | ConfigField::VddStaticAnalysisAutoDetect
            | ConfigField::VddTrackingPersist
            | ConfigField::VddTrackingLogAdversaryResponses
            | ConfigField::PermissionsEnabled
            | ConfigField::Provider {
                field: ProviderField::ThinkingEnabled | ProviderField::ThinkingAdaptive,
                ..
            } => "false",
        }
    }

    #[allow(clippy::too_many_lines)]
    fn assert_sample_applied(config: &AppConfig, field: ConfigField) {
        match field {
            ConfigField::ProxyPort => assert_eq!(config.proxy.port, 9123),
            ConfigField::ProxyHost => assert_eq!(config.proxy.host, "typed-env-value"),
            ConfigField::ProxyTarget => assert_eq!(config.proxy.target, "typed-env-value"),
            ConfigField::ProxyMaxResponseBytes => {
                assert_eq!(config.proxy.max_response_bytes, 7000);
            }
            ConfigField::Provider { name, field } => {
                let provider = &config.providers[name];
                match field {
                    ProviderField::ApiKey => assert!(provider
                        .api_key
                        .as_ref()
                        .is_some_and(|key| key.matches("typed-api-key-123"))),
                    ProviderField::BaseUrl => {
                        assert_eq!(provider.base_url, "https://typed-env.example/v1");
                    }
                    ProviderField::Model => {
                        assert_eq!(provider.model.as_deref(), Some("typed-env-value"));
                    }
                    ProviderField::Headers => {
                        assert_eq!(provider.headers.len(), 1);
                        assert!(provider
                            .headers
                            .matches_value("x-typed-env", "secret-header-value"));
                    }
                    ProviderField::ThinkingEnabled => assert!(!provider.thinking.enabled),
                    ProviderField::ThinkingBudgetTokens => {
                        assert_eq!(provider.thinking.budget_tokens, Some(7));
                    }
                    ProviderField::ThinkingPreserveAcrossTurns => {
                        assert!(provider.thinking.preserve_across_turns);
                    }
                    ProviderField::ThinkingReasoningEffort => {
                        assert_eq!(provider.thinking.reasoning_effort.as_deref(), Some("high"));
                    }
                    ProviderField::ThinkingAdaptive => assert!(!provider.thinking.adaptive),
                }
            }
            ConfigField::SessionTimeoutMinutes => {
                assert_eq!(config.session.timeout_minutes, 77);
            }
            ConfigField::SessionPersistPath => {
                assert_eq!(
                    config.session.persist_path,
                    std::path::Path::new("typed-env-value")
                );
            }
            ConfigField::SessionMaxTurns => assert_eq!(config.session.max_turns, 7),
            ConfigField::SessionTokenTrackingEnabled => {
                assert!(!config.session.token_tracking.enabled);
            }
            ConfigField::SessionTokenTrackingLogUsage => {
                assert!(!config.session.token_tracking.log_usage);
            }
            ConfigField::SessionTokenTrackingWarnThreshold => {
                assert!((config.session.token_tracking.warn_threshold - 0.25).abs() < f32::EPSILON);
            }
            ConfigField::SessionTokenTrackingMaxOutputTokens => {
                assert_eq!(config.session.token_tracking.max_output_tokens, 7);
            }
            ConfigField::VddEnabled => assert!(config.vdd.enabled),
            ConfigField::VddMode => assert_eq!(config.vdd.mode, VddMode::Blocking),
            ConfigField::VddAdversaryProvider => {
                assert_eq!(config.vdd.adversary.provider, "typed-env-value");
            }
            ConfigField::VddAdversaryModel => {
                assert_eq!(
                    config.vdd.adversary.model.as_deref(),
                    Some("typed-env-value")
                );
            }
            ConfigField::VddAdversaryApiKey => assert!(config
                .vdd
                .adversary
                .api_key
                .as_ref()
                .is_some_and(|key| key.matches("typed-api-key-123"))),
            ConfigField::VddAdversaryTemperature => {
                assert!((config.vdd.adversary.temperature - 0.25).abs() < f32::EPSILON);
            }
            ConfigField::VddAdversaryMaxTokens => {
                assert_eq!(config.vdd.adversary.max_tokens, 7);
            }
            ConfigField::VddAdversaryRequestTimeoutSeconds => {
                assert_eq!(config.vdd.adversary.request_timeout_seconds, 77);
            }
            ConfigField::VddThresholdsMaxIterations => {
                assert_eq!(config.vdd.thresholds.max_iterations, 7);
            }
            ConfigField::VddThresholdsFalsePositiveRate => {
                assert!((config.vdd.thresholds.false_positive_rate - 0.25).abs() < f32::EPSILON);
            }
            ConfigField::VddThresholdsMinIterations => {
                assert_eq!(config.vdd.thresholds.min_iterations, 1);
            }
            ConfigField::VddStaticAnalysisEnabled => {
                assert!(!config.vdd.static_analysis.enabled);
            }
            ConfigField::VddStaticAnalysisAutoDetect => {
                assert!(!config.vdd.static_analysis.auto_detect);
            }
            ConfigField::VddStaticAnalysisCommands => {
                assert_eq!(config.vdd.static_analysis.commands, ["typed-env-value"]);
            }
            ConfigField::VddStaticAnalysisTimeoutSeconds => {
                assert_eq!(config.vdd.static_analysis.timeout_seconds, 77);
            }
            ConfigField::VddTrackingPersist => assert!(!config.vdd.tracking.persist),
            ConfigField::VddTrackingPath => {
                assert_eq!(
                    config.vdd.tracking.path,
                    std::path::Path::new("typed-env-value")
                );
            }
            ConfigField::VddTrackingLogAdversaryResponses => {
                assert!(!config.vdd.tracking.log_adversary_responses);
            }
            ConfigField::GuardrailsBlastRadiusEnabled => {
                assert!(config.guardrails.blast_radius.as_ref().unwrap().enabled);
            }
            ConfigField::GuardrailsBlastRadiusMode => assert_eq!(
                config.guardrails.blast_radius.as_ref().unwrap().mode,
                GuardrailMode::Strict
            ),
            ConfigField::GuardrailsBlastRadiusAllowedPaths => assert_eq!(
                config
                    .guardrails
                    .blast_radius
                    .as_ref()
                    .unwrap()
                    .allowed_paths,
                ["typed-env-value"]
            ),
            ConfigField::GuardrailsBlastRadiusDeniedPaths => assert_eq!(
                config
                    .guardrails
                    .blast_radius
                    .as_ref()
                    .unwrap()
                    .denied_paths,
                ["typed-env-value"]
            ),
            ConfigField::GuardrailsBlastRadiusMaxFilesPerRun => assert_eq!(
                config
                    .guardrails
                    .blast_radius
                    .as_ref()
                    .unwrap()
                    .max_files_per_run
                    .map(NonZeroU32::get),
                Some(7)
            ),
            ConfigField::GuardrailsBlastRadiusMaxLinesPerRun => assert_eq!(
                config
                    .guardrails
                    .blast_radius
                    .as_ref()
                    .unwrap()
                    .max_lines_per_run
                    .map(NonZeroU32::get),
                Some(7)
            ),
            ConfigField::GuardrailsBlastRadiusMaxToolCallsPerRun => assert_eq!(
                config
                    .guardrails
                    .blast_radius
                    .as_ref()
                    .unwrap()
                    .max_tool_calls_per_run
                    .map(NonZeroU32::get),
                Some(7)
            ),
            ConfigField::GuardrailsBlastRadiusMaxMutationsPerRun => assert_eq!(
                config
                    .guardrails
                    .blast_radius
                    .as_ref()
                    .unwrap()
                    .max_mutations_per_run
                    .map(NonZeroU32::get),
                Some(7)
            ),
            ConfigField::GuardrailsDiffMonitorEnabled => {
                assert!(config.guardrails.diff_monitor.as_ref().unwrap().enabled);
            }
            ConfigField::GuardrailsDiffMonitorMaxLinesChanged => assert_eq!(
                config
                    .guardrails
                    .diff_monitor
                    .as_ref()
                    .unwrap()
                    .max_lines_changed,
                7
            ),
            ConfigField::GuardrailsDiffMonitorMaxFilesChanged => assert_eq!(
                config
                    .guardrails
                    .diff_monitor
                    .as_ref()
                    .unwrap()
                    .max_files_changed,
                7
            ),
            ConfigField::GuardrailsDiffMonitorAction => assert_eq!(
                config.guardrails.diff_monitor.as_ref().unwrap().action,
                GuardrailAction::Block
            ),
            ConfigField::GuardrailsQualityGatesEnabled => {
                assert!(config.guardrails.quality_gates.as_ref().unwrap().enabled);
            }
            ConfigField::GuardrailsQualityGatesRunAfter => assert_eq!(
                config.guardrails.quality_gates.as_ref().unwrap().run_after,
                RunAfter::OnCommit
            ),
            ConfigField::GuardrailsQualityGatesFailAction => assert_eq!(
                config
                    .guardrails
                    .quality_gates
                    .as_ref()
                    .unwrap()
                    .fail_action,
                GuardrailAction::Block
            ),
            ConfigField::GuardrailsQualityGatesChecks => {
                let checks = &config.guardrails.quality_gates.as_ref().unwrap().checks;
                assert_eq!(checks.len(), 1);
                assert_eq!(checks[0].name, "typed-env");
                assert_eq!(checks[0].command, "true");
                assert!(!checks[0].required);
            }
            ConfigField::GuardrailsQualityGatesTimeoutSeconds => assert_eq!(
                config
                    .guardrails
                    .quality_gates
                    .as_ref()
                    .unwrap()
                    .timeout_seconds,
                77
            ),
            ConfigField::PermissionsEnabled => assert!(!config.permissions.enabled),
            ConfigField::PermissionsDefaultAllow => {
                assert_eq!(config.permissions.default_allow, ["typed-env-value"]);
            }
            ConfigField::PermissionsMcp => {
                assert_eq!(config.permissions.mcp.len(), 1);
                assert_eq!(config.permissions.mcp["typed-server"], ["typed-tool"]);
            }
            ConfigField::MemoryAutomaticLearningEnabled => {
                assert!(config.memory.automatic_learning_enabled);
            }
            ConfigField::MemoryTeamId => assert_eq!(
                config
                    .memory
                    .team_id
                    .as_ref()
                    .map(crate::team_memory::TeamId::as_str),
                Some("team-0123456789abcdef0123456789abcdef")
            ),
            ConfigField::MemoryTeamMemoryPath => assert_eq!(
                config.memory.team_memory_path.as_deref(),
                Some(std::path::Path::new("typed-env-value"))
            ),
            ConfigField::WebFetchDistillationEnabled => {
                assert!(config.web_fetch.distillation_enabled);
            }
            ConfigField::WebFetchMaxDistillationBytes => {
                assert_eq!(config.web_fetch.max_distillation_bytes, 7000);
            }
            ConfigField::WebFetchDistillationProvider => assert_eq!(
                config.web_fetch.distillation_provider.as_deref(),
                Some("typed-env-value")
            ),
            ConfigField::WebFetchDistillationModel => assert_eq!(
                config.web_fetch.distillation_model.as_deref(),
                Some("typed-env-value")
            ),
            ConfigField::WebFetchPreapprovedDomains => {
                assert_eq!(config.web_fetch.preapproved_domains, ["typed-env-value"]);
            }
            ConfigField::WebFetchExactPrivateOrigins => {
                assert_eq!(
                    config.web_fetch.exact_private_origins,
                    ["http://127.0.0.1:8787"]
                );
            }
            ConfigField::PolicyMaxRequestTokens => {
                assert_eq!(config.policy.max_request_tokens, Some(7000));
            }
            ConfigField::PolicyMaxSessionTokens => {
                assert_eq!(config.policy.max_session_tokens, Some(7000));
            }
            ConfigField::PolicyToolCaps => {
                assert_eq!(config.policy.tool_caps.len(), 1);
                assert_eq!(config.policy.tool_caps["typed-tool"], 7);
            }
            ConfigField::PolicyModelAllowlist => {
                assert_eq!(config.policy.model_allowlist.len(), 1);
                assert!(config.policy.model_allowlist.contains("typed-model"));
            }
        }
    }

    #[test]
    fn every_registered_name_round_trips_to_its_typed_field() {
        for definition in registry() {
            for variable in &definition.variables {
                let mut config = app_config();
                apply_environment(
                    &mut config,
                    [(
                        OsString::from(&variable.name),
                        OsString::from(sample_for(definition.field)),
                    )],
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "{} must configure {}: {error}",
                        variable.name, definition.config_field
                    )
                });
                assert_sample_applied(&config, definition.field);
            }
        }
    }

    #[allow(clippy::too_many_lines)] // complete lower-file value for every registry field
    fn baseline_yaml() -> String {
        let mut yaml = String::from(
            r"proxy:
  port: 8001
  host: 127.0.0.1
  target: anthropic
  max_response_bytes: 6000
providers:
",
        );
        for provider in PROVIDERS {
            yaml.push_str("  ");
            yaml.push_str(provider.config_name);
            yaml.push_str(":\n    api_key: file-api-key-123\n    base_url: ");
            if matches!(
                provider.config_name,
                "ollama" | "local" | "lmstudio" | "localai" | "text-generation-webui"
            ) {
                yaml.push_str("http://localhost:1234/v1\n");
            } else {
                yaml.push_str("https://example.com/v1\n");
            }
            yaml.push_str(
                r"    model: file-model
    headers:
      x-file-source: file-header-value
    thinking:
      enabled: true
      budget_tokens: 3
      preserve_across_turns: false
      reasoning_effort: low
      adaptive: true
",
            );
        }
        yaml.push_str(
            r#"session:
  timeout_minutes: 31
  persist_path: file-sessions
  max_turns: 2
  token_tracking:
    enabled: true
    log_usage: true
    warn_threshold: 0.75
    max_output_tokens: 3
vdd:
  enabled: false
  mode: advisory
  adversary:
    provider: google
    model: file-adversary-model
    api_key: file-adversary-key
    temperature: 0.3
    max_tokens: 4
    request_timeout_seconds: 55
  thresholds:
    max_iterations: 5
    false_positive_rate: 0.75
    min_iterations: 2
  static_analysis:
    enabled: true
    auto_detect: true
    commands: ["file-check"]
    timeout_seconds: 66
  tracking:
    persist: true
    path: file-vdd
    log_adversary_responses: true
guardrails:
  blast_radius:
    enabled: false
    mode: advisory
    allowed_paths: ["file-allowed"]
    denied_paths: ["file-denied"]
    max_files_per_run: 2
    max_lines_per_run: 2
    max_tool_calls_per_run: 2
    max_mutations_per_run: 2
  diff_monitor:
    enabled: false
    max_lines_changed: 500
    max_files_changed: 10
    action: warn
  quality_gates:
    enabled: false
    run_after: every_turn
    fail_action: warn
    checks:
      - name: file-check
        command: "true"
        required: true
    timeout_seconds: 120
permissions:
  enabled: true
  default_allow: ["Bash(git status)"]
  mcp:
    file-server: ["file-tool"]
memory:
  automatic_learning_enabled: false
  team_id: team-fedcba9876543210fedcba9876543210
  team_memory_path: file-memory
web_fetch:
  distillation_enabled: false
  max_distillation_bytes: 100000
  distillation_provider: anthropic
  distillation_model: file-distillation-model
  preapproved_domains: ["file.example"]
policy:
  max_request_tokens: 9000
  max_session_tokens: 9000
  tool_caps:
    file-tool: 2
  model_allowlist: ["file-model"]
"#,
        );
        yaml
    }

    #[test]
    fn every_canonical_name_overrides_file_state_before_typed_deserialization() {
        let yaml = baseline_yaml();
        for definition in registry() {
            let canonical = definition
                .variables
                .iter()
                .find(|variable| variable.deprecation == EnvironmentDeprecation::Current)
                .expect("every field has one canonical name");
            let builder = config::Config::builder()
                .add_source(config::File::from_str(&yaml, config::FileFormat::Yaml));
            let mut merged = builder.build().unwrap_or_else(|error| {
                panic!(
                    "{} must build for {}: {error}",
                    canonical.name, definition.config_field
                )
            });
            apply_environment_to_config(
                &mut merged,
                [(
                    OsString::from(&canonical.name),
                    OsString::from(sample_for(definition.field)),
                )],
            )
            .unwrap_or_else(|error| {
                panic!(
                    "{} must override {}: {error}",
                    canonical.name, definition.config_field
                )
            });
            let typed: AppConfig = merged.try_deserialize().unwrap_or_else(|error| {
                panic!(
                    "{} must deserialize into {}: {error}",
                    canonical.name, definition.config_field
                )
            });
            assert_sample_applied(&typed, definition.field);
        }
    }
}
