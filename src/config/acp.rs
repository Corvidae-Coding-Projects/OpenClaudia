//! ACP (Agent Client Protocol) server configuration.
//!
//! Closes crosslink #717 — the agentic loop in [`crate::acp::AcpServer`]
//! previously hard-coded its iteration ceiling. This module exposes the
//! knob as a typed config value so the cap is discoverable, configurable
//! at runtime via either YAML or env var, and testable without
//! recompiling.
//!
//! ## Why this isn't a field on [`crate::config::AppConfig`]
//!
//! Adding a field to `AppConfig` would force every in-tree struct
//! literal that constructs an `AppConfig` (test fixtures, subagent
//! scaffolding, vdd transport tests) to be updated in lockstep. Several
//! of those sites live in modules the present change-set is forbidden
//! to touch. So `AcpConfig` is loaded lazily on first use from the
//! optional `acp:` block of `.openclaudia/config.yaml` plus a single
//! env-var override — same configurability surface, no schema break.

use serde::{Deserialize, Deserializer};
use std::path::Path;

/// Default iteration ceiling for the ACP prompt → tool-call → re-prompt
/// loop. Matches the previous hard-coded value so existing deployments
/// see no behavioural change after this module lands.
const DEFAULT_MAX_ITERATIONS: u32 = 50;

/// Env-var override for [`AcpConfig::max_iterations`]. A non-empty,
/// parseable `u32` wins over both the default and any value read from
/// the YAML config file.
pub const MAX_ITERATIONS_ENV_VAR: &str = "OPENCLAUDIA_ACP_MAX_ITERATIONS";

const fn default_max_iterations() -> u32 {
    DEFAULT_MAX_ITERATIONS
}

fn deserialize_positive_max_iterations<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let value = u32::deserialize(deserializer)?;
    if value == 0 {
        return Err(serde::de::Error::custom(
            "max_iterations must be at least 1",
        ));
    }
    Ok(value)
}

/// ACP server configuration.
///
/// All fields default to the values previously hard-coded in
/// [`crate::acp::AcpServer::run_prompt_loop`] so omitting the section
/// from `config.yaml` reproduces today's behaviour exactly.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AcpConfig {
    /// Maximum number of provider request iterations within a single
    /// ACP prompt. Each tool call consumes one iteration; the loop
    /// returns `"end_turn"` as soon as the model stops issuing tool
    /// calls. The cap exists as a safety belt against runaway loops —
    /// a model that never decides to stop. Configurable so operators
    /// running long-horizon agents can raise it without forking.
    #[serde(
        default = "default_max_iterations",
        deserialize_with = "deserialize_positive_max_iterations"
    )]
    pub max_iterations: u32,
}

impl Default for AcpConfig {
    fn default() -> Self {
        Self {
            max_iterations: DEFAULT_MAX_ITERATIONS,
        }
    }
}

impl AcpConfig {
    /// Resolve the runtime [`AcpConfig`] from (in order of precedence):
    ///
    /// 1. The [`MAX_ITERATIONS_ENV_VAR`] env var, if set to a parseable,
    ///    non-zero `u32`.
    /// 2. The `acp:` block of `.openclaudia/config.yaml`, if present.
    /// 3. [`AcpConfig::default`].
    ///
    /// # Errors
    ///
    /// Returns an error when the YAML file is present but malformed, the
    /// `acp:` block has the wrong shape, `max_iterations` is zero, or the env
    /// var override is present but invalid. Missing files and absent `acp:`
    /// blocks still resolve to defaults.
    pub fn load() -> Result<Self, String> {
        let cfg = Self::load_from_yaml_path(Path::new(".openclaudia/config.yaml"))?;
        match std::env::var(MAX_ITERATIONS_ENV_VAR) {
            Ok(raw) => Self::apply_env_override(cfg, &raw),
            Err(std::env::VarError::NotPresent) => Ok(cfg),
            Err(std::env::VarError::NotUnicode(_)) => {
                Err(format!("{MAX_ITERATIONS_ENV_VAR} must be valid UTF-8"))
            }
        }
    }

    /// Read the `acp:` block out of `.openclaudia/config.yaml` if the
    /// file exists. Missing files or absent `acp:` blocks resolve to defaults.
    fn load_from_yaml_path(path: &Path) -> Result<Self, String> {
        let raw = match std::fs::read_to_string(path) {
            Ok(raw) => zeroize::Zeroizing::new(raw),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(format!("failed to read {}: {e}", path.display())),
        };
        Self::load_from_yaml_str(&raw)
    }

    fn load_from_yaml_str(raw: &str) -> Result<Self, String> {
        let root: serde_yaml::Value =
            serde_yaml::from_str(raw).map_err(|e| format!("invalid YAML: {e}"))?;
        if root.is_null() {
            return Ok(Self::default());
        }
        if !root.is_mapping() {
            return Err(format!(
                "expected config root to be a mapping, got {}",
                yaml_value_type_name(&root)
            ));
        }
        let Some(acp) = root.get("acp") else {
            return Ok(Self::default());
        };
        let cfg: Self = serde_yaml::from_value(acp.clone())
            .map_err(|e| format!("invalid acp config block: {e}"))?;
        cfg.validate()
    }

    fn apply_env_override(mut cfg: Self, raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(cfg);
        }
        let parsed = trimmed.parse::<u32>().map_err(|e| {
            format!("{MAX_ITERATIONS_ENV_VAR} must be a positive integer, got {trimmed:?}: {e}")
        })?;
        if parsed == 0 {
            return Err(format!("{MAX_ITERATIONS_ENV_VAR} must be at least 1"));
        }
        cfg.max_iterations = parsed;
        Ok(cfg)
    }

    fn validate(self) -> Result<Self, String> {
        if self.max_iterations == 0 {
            return Err("acp.max_iterations must be at least 1".to_string());
        }
        Ok(self)
    }
}

const fn yaml_value_type_name(value: &serde_yaml::Value) -> &'static str {
    match value {
        serde_yaml::Value::Null => "null",
        serde_yaml::Value::Bool(_) => "boolean",
        serde_yaml::Value::Number(_) => "number",
        serde_yaml::Value::String(_) => "string",
        serde_yaml::Value::Sequence(_) => "sequence",
        serde_yaml::Value::Mapping(_) => "mapping",
        serde_yaml::Value::Tagged(_) => "tagged",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_max_iterations_matches_previous_hard_coded_value() {
        // crosslink #717: the cap was `50` as a local literal before this
        // module existed. Default must match exactly so config-less
        // deployments see no behavioural change.
        assert_eq!(AcpConfig::default().max_iterations, 50);
    }

    #[test]
    fn empty_yaml_yields_default() {
        let cfg: AcpConfig = serde_yaml::from_str("{}").expect("valid yaml");
        assert_eq!(cfg.max_iterations, 50);
    }

    #[test]
    fn deserialises_custom_max_iterations_from_yaml() {
        let yaml = "max_iterations: 200\n";
        let cfg: AcpConfig = serde_yaml::from_str(yaml).expect("valid yaml");
        assert_eq!(cfg.max_iterations, 200);
    }

    #[test]
    fn deserialisation_rejects_zero_max_iterations() {
        let err = serde_yaml::from_str::<AcpConfig>("max_iterations: 0\n")
            .expect_err("zero cap must be invalid");

        assert!(err.to_string().contains("at least 1"), "{err}");
    }

    #[test]
    fn load_from_yaml_str_defaults_when_acp_block_absent() {
        let cfg = AcpConfig::load_from_yaml_str("proxy:\n  target: anthropic\n")
            .expect("missing acp block should use defaults");

        assert_eq!(cfg, AcpConfig::default());
    }

    #[test]
    fn load_from_yaml_str_reads_acp_block() {
        let cfg = AcpConfig::load_from_yaml_str("acp:\n  max_iterations: 123\n")
            .expect("valid acp block should load");

        assert_eq!(cfg.max_iterations, 123);
    }

    #[test]
    fn load_from_yaml_str_rejects_malformed_yaml() {
        let err = AcpConfig::load_from_yaml_str("acp: [").expect_err("bad YAML must fail");

        assert!(err.contains("invalid YAML"), "{err}");
    }

    #[test]
    fn load_from_yaml_str_rejects_non_mapping_root() {
        let err =
            AcpConfig::load_from_yaml_str("- acp").expect_err("non-mapping config root must fail");

        assert!(err.contains("mapping"), "{err}");
        assert!(err.contains("sequence"), "{err}");
    }

    #[test]
    fn load_from_yaml_str_rejects_unknown_acp_field() {
        let err = AcpConfig::load_from_yaml_str("acp:\n  max_iteration: 10\n")
            .expect_err("typoed acp field must fail");

        assert!(err.contains("invalid acp config block"), "{err}");
        assert!(err.contains("max_iteration"), "{err}");
    }

    #[test]
    fn load_from_yaml_str_rejects_zero_acp_iterations() {
        let err = AcpConfig::load_from_yaml_str("acp:\n  max_iterations: 0\n")
            .expect_err("zero acp cap must fail");

        assert!(err.contains("at least 1"), "{err}");
    }

    #[test]
    fn env_override_wins_when_positive_integer() {
        let cfg = AcpConfig::apply_env_override(AcpConfig { max_iterations: 10 }, "200")
            .expect("valid env override should apply");

        assert_eq!(cfg.max_iterations, 200);
    }

    #[test]
    fn env_override_rejects_invalid_value() {
        let err = AcpConfig::apply_env_override(AcpConfig::default(), "many")
            .expect_err("invalid env override must fail");

        assert!(err.contains(MAX_ITERATIONS_ENV_VAR), "{err}");
        assert!(err.contains("positive integer"), "{err}");
    }

    #[test]
    fn env_override_rejects_zero() {
        let err = AcpConfig::apply_env_override(AcpConfig::default(), "0")
            .expect_err("zero env override must fail");

        assert!(err.contains(MAX_ITERATIONS_ENV_VAR), "{err}");
        assert!(err.contains("at least 1"), "{err}");
    }

    #[test]
    fn env_override_empty_string_is_ignored() {
        let cfg = AcpConfig::apply_env_override(AcpConfig { max_iterations: 25 }, "   ")
            .expect("empty env override should be ignored");

        assert_eq!(cfg.max_iterations, 25);
    }

    #[test]
    fn env_var_constant_is_namespaced_under_openclaudia_acp() {
        // Guard against accidental rename: the env var is documented in
        // the module docstring above. Keep the OPENCLAUDIA_ prefix so
        // it aligns with the prefix used by the main config builder.
        assert_eq!(MAX_ITERATIONS_ENV_VAR, "OPENCLAUDIA_ACP_MAX_ITERATIONS");
    }
}
