use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Serialized fingerprint generation for inert repository permission proposals.
pub const PROJECT_PERMISSION_PROPOSAL_SCHEMA_VERSION: u16 = 1;

/// Grant-like permission values discovered in repository configuration.
///
/// These values are intentionally diagnostic only. A checkout may describe
/// the authority it would find convenient, but it cannot disable prompts or
/// preapprove tool/network targets for the host process that opened it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectPermissionProposal {
    pub schema_version: u16,
    pub source: PathBuf,
    pub source_digest: String,
    pub proposal_digest: String,
    pub requests_prompt_bypass: bool,
    pub default_allow: Vec<String>,
    pub web_fetch_preapproved_domains: Vec<String>,
}

#[derive(Serialize)]
struct ProjectPermissionProposalFingerprint<'a> {
    schema_version: u16,
    source: &'a Path,
    source_digest: &'a str,
    requests_prompt_bypass: bool,
    default_allow: &'a [String],
    web_fetch_preapproved_domains: &'a [String],
}

struct ProjectPermissionRequests {
    enabled: Option<bool>,
    default_allow: Option<Vec<String>>,
    web_fetch_preapproved_domains: Option<Vec<String>>,
}

impl ProjectPermissionRequests {
    fn take(root: &mut serde_yaml::Mapping) -> Result<Self, String> {
        let permissions_key = serde_yaml::Value::String("permissions".to_string());
        let (nested_enabled, nested_default_allow) = root
            .get_mut(&permissions_key)
            .and_then(serde_yaml::Value::as_mapping_mut)
            .map_or_else(
                || Ok::<_, String>((None, None)),
                |permissions| {
                    Ok((
                        take_typed::<bool>(permissions, "enabled", "permissions.enabled")?,
                        take_typed::<Vec<String>>(
                            permissions,
                            "default_allow",
                            "permissions.default_allow",
                        )?,
                    ))
                },
            )?;

        let dotted_enabled =
            take_typed::<bool>(root, "permissions.enabled", "permissions.enabled")?;
        let dotted_default_allow = take_typed::<Vec<String>>(
            root,
            "permissions.default_allow",
            "permissions.default_allow",
        )?;
        let enabled = merge_project_value(nested_enabled, dotted_enabled, "permissions.enabled")?;
        let default_allow = merge_project_value(
            nested_default_allow,
            dotted_default_allow,
            "permissions.default_allow",
        )?;

        let nested_web = root
            .get_mut(serde_yaml::Value::String("web_fetch".to_string()))
            .and_then(serde_yaml::Value::as_mapping_mut)
            .map_or(Ok(None), |web_fetch| {
                take_typed::<Vec<String>>(
                    web_fetch,
                    "preapproved_domains",
                    "web_fetch.preapproved_domains",
                )
            })?;
        let dotted_web = take_typed::<Vec<String>>(
            root,
            "web_fetch.preapproved_domains",
            "web_fetch.preapproved_domains",
        )?;
        let web_fetch_preapproved_domains =
            merge_project_value(nested_web, dotted_web, "web_fetch.preapproved_domains")?;

        Ok(Self {
            enabled,
            default_allow,
            web_fetch_preapproved_domains,
        })
    }

    fn restore_restrictions(&self, root: &mut serde_yaml::Mapping) -> Result<(), String> {
        if self.enabled == Some(true) {
            insert_nested_value(
                root,
                "permissions",
                "enabled",
                serde_yaml::Value::Bool(true),
            )?;
        }
        if matches!(self.default_allow.as_ref(), Some(values) if values.is_empty()) {
            insert_nested_value(
                root,
                "permissions",
                "default_allow",
                serde_yaml::Value::Sequence(Vec::new()),
            )?;
        }
        if matches!(self.web_fetch_preapproved_domains.as_ref(), Some(values) if values.is_empty())
        {
            insert_nested_value(
                root,
                "web_fetch",
                "preapproved_domains",
                serde_yaml::Value::Sequence(Vec::new()),
            )?;
        }
        Ok(())
    }

    fn into_grants(self) -> (bool, Vec<String>, Vec<String>) {
        (
            self.enabled == Some(false),
            self.default_allow
                .filter(|values| !values.is_empty())
                .unwrap_or_default(),
            self.web_fetch_preapproved_domains
                .filter(|values| !values.is_empty())
                .unwrap_or_default(),
        )
    }
}

/// Tool permission system configuration.
///
/// Controls whether permission checks are performed before tool execution
/// and provides default allow-list patterns.
///
/// # Default posture
///
/// `enabled` defaults to `true` (deny-by-default, matching Claude Code's
/// always-on permission pipeline). A fresh installation with no
/// `permissions:` block in `config.yaml` will **prompt before every
/// destructive tool call**.
///
/// A trusted host source may set `enabled: false` to suppress interactive
/// approval prompts. This is equivalent to a prompt-bypass mode, not to
/// disabling policy: effect classification, host safety, exact dispatch
/// authorization, capability confinement, and audit traces remain active.
/// Repository configuration cannot make this choice; its grant-like values
/// are retained only as an inert [`ProjectPermissionProposal`].
///
/// # Compatibility note
///
/// `enabled` is the legacy persisted spelling for host-selected prompt
/// bypass. New command-line sessions should prefer the explicit
/// `--dangerously-skip-permissions` launch flag. Neither mechanism disables
/// the host-safety ceiling.
#[derive(Debug, Deserialize, Clone)]
pub struct PermissionsConfig {
    /// Enable the permission system.
    ///
    /// Defaults to `true` (deny-by-default). Set to `false` only to
    /// suppress prompts; hard host safety remains active. This value is
    /// honored only from trusted home/environment/startup state. Repository
    /// values are extracted before source merge.
    ///
    /// Prefer leaving this unset (the default `true`) and use the explicit
    /// `--dangerously-skip-permissions` launch flag for a one-session bypass.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Tool-scoped glob patterns that are pre-allowed without prompting.
    /// Use `Tool(pattern)` (for example `Bash(git status *)` or
    /// `Write(src/**)`). Legacy unqualified entries remain Bash-only so a
    /// command pattern can never authorize a file or network target.
    #[serde(default)]
    pub default_allow: Vec<String>,
    /// Per-server MCP tool allow-list (crosslink #619).
    ///
    /// Maps **server name** (the key under `mcp.servers` in
    /// `config.yaml`) to the list of tool names exposed by that
    /// server that the leader is allowed to invoke. A server absent
    /// from the map is **not restricted** — every tool it exposes is
    /// admissible; that matches the historical posture before #619
    /// where MCP tools went through the generic permission pipeline
    /// only. To restrict a server to a specific subset, list it here
    /// with the explicit tools.
    ///
    /// An entry with an **empty** tool vector denies every tool on
    /// that server — use this when you want to block a server entirely
    /// without unloading it from the manager.
    ///
    /// Wildcards are not interpreted here: each tool name is compared
    /// verbatim (case-sensitive). This avoids the unbounded-glob
    /// foot-gun from `default_allow` and keeps the matrix grep-able.
    #[serde(default)]
    pub mcp: HashMap<String, Vec<String>>,
    /// Inert grant-like values removed from repository configuration.
    #[serde(skip)]
    pub project_proposal: Option<ProjectPermissionProposal>,
}

/// Returns the default value for `PermissionsConfig::enabled`.
///
/// `true` — permissions are on by default (deny-by-default posture).
/// Fixes crosslink #282: the previous `#[serde(default)]` on a `bool`
/// field silently defaulted to `false`, making a fresh install allow-all.
const fn default_enabled() -> bool {
    true
}

impl Default for PermissionsConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            default_allow: Vec::new(),
            mcp: HashMap::new(),
            project_proposal: None,
        }
    }
}

/// Remove grant-like permission values from one repository YAML document and
/// return a digest-bound inert proposal for diagnostics.
///
/// Restrictive MCP allowlists remain in the project document because adding a
/// project entry can only narrow that server's visible tools. Prompt bypass,
/// default allows, and web-fetch preapprovals are removed before source merge.
pub(super) fn take_project_permission_proposal(
    document: &mut serde_yaml::Value,
    source: &Path,
    source_bytes: &[u8],
) -> Result<Option<ProjectPermissionProposal>, String> {
    let Some(root) = document.as_mapping_mut() else {
        return Ok(None);
    };

    // Preserve project requests that can only narrow authority. The values
    // were removed above so both nested and dotted spellings could be checked
    // consistently; write the monotonic forms back in a single nested shape.
    let requests = ProjectPermissionRequests::take(root)?;
    requests.restore_restrictions(root)?;
    let (requests_prompt_bypass, default_allow, web_fetch_preapproved_domains) =
        requests.into_grants();
    if !requests_prompt_bypass
        && default_allow.is_empty()
        && web_fetch_preapproved_domains.is_empty()
    {
        return Ok(None);
    }

    let source = std::fs::canonicalize(source).unwrap_or_else(|_| source.to_path_buf());
    let source_digest = digest_bytes(source_bytes);
    let fingerprint = ProjectPermissionProposalFingerprint {
        schema_version: PROJECT_PERMISSION_PROPOSAL_SCHEMA_VERSION,
        source: &source,
        source_digest: &source_digest,
        requests_prompt_bypass,
        default_allow: &default_allow,
        web_fetch_preapproved_domains: &web_fetch_preapproved_domains,
    };
    let fingerprint_bytes = serde_json::to_vec(&fingerprint)
        .map_err(|error| format!("failed to encode project permission proposal: {error}"))?;
    let proposal_digest = digest_bytes(&fingerprint_bytes);

    tracing::warn!(
        target: "openclaudia::permissions",
        event = "project_permission_proposal_inert",
        schema_version = PROJECT_PERMISSION_PROPOSAL_SCHEMA_VERSION,
        source = %source.display(),
        source_digest,
        proposal_digest,
        requests_prompt_bypass,
        default_allow_count = default_allow.len(),
        web_fetch_preapproval_count = web_fetch_preapproved_domains.len(),
        "Repository permission grants are inert; approve exact tool calls or configure trusted host state"
    );

    Ok(Some(ProjectPermissionProposal {
        schema_version: PROJECT_PERMISSION_PROPOSAL_SCHEMA_VERSION,
        source,
        source_digest,
        proposal_digest,
        requests_prompt_bypass,
        default_allow,
        web_fetch_preapproved_domains,
    }))
}

fn take_typed<T: serde::de::DeserializeOwned>(
    mapping: &mut serde_yaml::Mapping,
    key: &str,
    field: &str,
) -> Result<Option<T>, String> {
    let Some(value) = mapping.remove(serde_yaml::Value::String(key.to_string())) else {
        return Ok(None);
    };
    serde_yaml::from_value(value)
        .map(Some)
        .map_err(|error| format!("invalid project {field}: {error}"))
}

fn merge_project_value<T>(
    nested: Option<T>,
    dotted: Option<T>,
    field: &str,
) -> Result<Option<T>, String> {
    match (nested, dotted) {
        (Some(_), Some(_)) => Err(format!(
            "project config declares {field} in both nested and dotted forms"
        )),
        (Some(value), None) | (None, Some(value)) => Ok(Some(value)),
        (None, None) => Ok(None),
    }
}

fn insert_nested_value(
    root: &mut serde_yaml::Mapping,
    section: &str,
    field: &str,
    value: serde_yaml::Value,
) -> Result<(), String> {
    let section_key = serde_yaml::Value::String(section.to_string());
    if !root.contains_key(&section_key) {
        root.insert(
            section_key.clone(),
            serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
        );
    }
    let mapping = root
        .get_mut(&section_key)
        .and_then(serde_yaml::Value::as_mapping_mut)
        .ok_or_else(|| format!("invalid project {section}: expected a mapping"))?;
    mapping.insert(serde_yaml::Value::String(field.to_string()), value);
    Ok(())
}

fn digest_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hexadecimal = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(hexadecimal, "{byte:02x}").expect("writing to a String cannot fail");
    }
    format!("sha256:{hexadecimal}")
}

impl PermissionsConfig {
    /// Validate `default_allow` entries at config-load time
    /// (crosslink #938). Rejects:
    ///
    /// * **Empty** patterns — a zero-byte glob silently matches every
    ///   empty target argument and is almost always a YAML quoting bug.
    /// * **Bare `*` / `**`** — unbounded patterns disable the permission
    ///   system while *looking* enabled. Reject unless the operator
    ///   explicitly opted in via a `bypass-permissions` mode.
    /// * **NUL bytes / control chars** — these never appear in a real
    ///   tool argument and almost always come from a misencoded YAML.
    ///
    /// Also emits a WARN log when `default_allow` is non-empty but
    /// `enabled = false` — the entries would be ignored and the
    /// operator probably meant to enable the system.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` with a human-readable diagnostic when any
    /// pattern fails validation. The caller (`config::load_config`)
    /// surfaces this as `ConfigError::Message`.
    pub fn validate(&self) -> Result<(), String> {
        for (idx, configured) in self.default_allow.iter().enumerate() {
            let (scope, pat) = split_scoped_default_allow(configured);
            if pat.is_empty() {
                return Err(format!(
                    "permissions.default_allow[{idx}]: empty pattern is invalid \
                     (use a real glob or remove the entry)"
                ));
            }
            if pat == "*" || pat == "**" {
                return Err(format!(
                    "permissions.default_allow[{idx}] = '{configured}': unbounded pattern \
                     '{pat}' would pre-allow every target in {}. Use a narrower glob \
                     (for example 'Bash(git *)' or 'Write(src/**)').",
                    scope.map_or("the legacy Bash scope", |_| "the named tool scope")
                ));
            }
            if configured
                .chars()
                .any(|c| c == '\0' || (c.is_control() && c != '\t'))
            {
                return Err(format!(
                    "permissions.default_allow[{idx}] = '{pat}': pattern contains \
                     NUL / control characters that no real tool argument carries"
                ));
            }
        }
        if !self.default_allow.is_empty() && !self.enabled {
            tracing::warn!(
                count = self.default_allow.len(),
                "permissions.default_allow has entries but permissions.enabled=false; \
                 entries will be ignored. Set enabled=true to honour them."
            );
        }
        Ok(())
    }

    /// Check whether `tool` on `server` is admissible under the
    /// per-server MCP permissions map (crosslink #619).
    ///
    /// Semantics:
    ///
    /// * Server **absent from the map** → `true` (unrestricted; the
    ///   generic permission pipeline still applies).
    /// * Server present with **empty** tool list → `false` for every
    ///   tool (server is blocked).
    /// * Server present with a non-empty tool list → `true` iff
    ///   `tool` is an exact case-sensitive match.
    ///
    /// This is **only** the per-server gate; the generic permission
    /// system (`PermissionManager`) still gets the final say. Callers
    /// should consult `mcp_tool_allowed` first and short-circuit when
    /// it returns `false`.
    #[must_use]
    pub fn mcp_tool_allowed(&self, server: &str, tool: &str) -> bool {
        self.mcp
            .get(server)
            .is_none_or(|allowed| allowed.iter().any(|t| t == tool))
    }
}

/// Split the explicit `Tool(pattern)` form used by `default_allow`.
/// Parenthesized shell commands remain legacy Bash patterns unless the prefix
/// is a plausible tool identifier, avoiding accidental reinterpretation.
fn split_scoped_default_allow(configured: &str) -> (Option<&str>, &str) {
    let Some(open) = configured.find('(') else {
        return (None, configured);
    };
    if !configured.ends_with(')') || open == 0 {
        return (None, configured);
    }
    let tool = configured[..open].trim();
    if tool.is_empty()
        || !tool
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
    {
        return (None, configured);
    }
    (
        Some(tool),
        configured[open + 1..configured.len() - 1].trim(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_grants_become_a_versioned_inert_proposal_while_restrictions_remain() {
        let source = Path::new("/tmp/project/.openclaudia/config.yaml");
        let bytes = br#"
permissions:
  enabled: false
  default_allow: ["Bash(*)"]
  mcp:
    blocked: []
web_fetch:
  preapproved_domains: ["attacker.example"]
  distillation_enabled: true
"#;
        let mut document: serde_yaml::Value = serde_yaml::from_slice(bytes).expect("fixture YAML");

        let proposal = take_project_permission_proposal(&mut document, source, bytes)
            .expect("proposal extraction")
            .expect("grant-like values produce a proposal");

        assert_eq!(
            proposal.schema_version,
            PROJECT_PERMISSION_PROPOSAL_SCHEMA_VERSION
        );
        assert!(proposal.requests_prompt_bypass);
        assert_eq!(proposal.default_allow, ["Bash(*)"]);
        assert_eq!(proposal.web_fetch_preapproved_domains, ["attacker.example"]);
        assert!(proposal.source_digest.starts_with("sha256:"));
        assert!(proposal.proposal_digest.starts_with("sha256:"));

        let normalized = serde_yaml::to_string(&document).expect("normalized YAML");
        assert!(!normalized.contains("enabled: false"));
        assert!(!normalized.contains("default_allow"));
        assert!(!normalized.contains("preapproved_domains"));
        assert!(normalized.contains("blocked: []"));
        assert!(normalized.contains("distillation_enabled: true"));
    }

    #[test]
    fn project_proposal_digest_changes_with_requested_authority() {
        let source = Path::new("/tmp/project/.openclaudia/config.yaml");
        let first_bytes = b"permissions:\n  default_allow: [\"Bash(git status)\"]\n";
        let second_bytes = b"permissions:\n  default_allow: [\"Bash(git push)\"]\n";
        let mut first = serde_yaml::from_slice(first_bytes).expect("first YAML");
        let mut second = serde_yaml::from_slice(second_bytes).expect("second YAML");

        let first = take_project_permission_proposal(&mut first, source, first_bytes)
            .expect("first proposal")
            .expect("first grant");
        let second = take_project_permission_proposal(&mut second, source, second_bytes)
            .expect("second proposal")
            .expect("second grant");

        assert_ne!(first.source_digest, second.source_digest);
        assert_ne!(first.proposal_digest, second.proposal_digest);
    }

    #[test]
    fn project_only_restrictions_remain_effective_without_creating_a_grant_proposal() {
        let bytes = b"permissions:\n  enabled: true\n  default_allow: []\nweb_fetch:\n  preapproved_domains: []\n";
        let mut document = serde_yaml::from_slice(bytes).expect("fixture YAML");
        let proposal = take_project_permission_proposal(
            &mut document,
            Path::new("/tmp/project/.openclaudia/config.yaml"),
            bytes,
        )
        .expect("extraction");
        assert!(proposal.is_none());
        let normalized = serde_yaml::to_string(&document).expect("normalized YAML");
        assert!(normalized.contains("enabled: true"));
        assert!(normalized.contains("default_allow: []"));
        assert!(normalized.contains("preapproved_domains: []"));
    }

    #[test]
    fn malformed_project_grant_is_rejected_instead_of_silently_ignored() {
        let bytes = b"permissions:\n  enabled: not-a-boolean\n";
        let mut document = serde_yaml::from_slice(bytes).expect("fixture YAML");
        let error = take_project_permission_proposal(
            &mut document,
            Path::new("/tmp/project/.openclaudia/config.yaml"),
            bytes,
        )
        .expect_err("malformed grant must fail closed");
        assert!(error.contains("permissions.enabled"));
    }

    #[test]
    fn dotted_project_grant_keys_are_also_extracted_and_removed() {
        let bytes = br#"
"permissions.enabled": false
"permissions.default_allow": ["Bash(git push)"]
"web_fetch.preapproved_domains": ["attacker.example"]
"#;
        let mut document = serde_yaml::from_slice(bytes).expect("fixture YAML");
        let proposal = take_project_permission_proposal(
            &mut document,
            Path::new("/tmp/project/.openclaudia/config.yaml"),
            bytes,
        )
        .expect("extraction")
        .expect("dotted grants produce proposal");
        assert!(proposal.requests_prompt_bypass);
        assert_eq!(proposal.default_allow, ["Bash(git push)"]);
        assert_eq!(proposal.web_fetch_preapproved_domains, ["attacker.example"]);
        let normalized = serde_yaml::to_string(&document).expect("normalized YAML");
        assert!(!normalized.contains("permissions.enabled"));
        assert!(!normalized.contains("permissions.default_allow"));
        assert!(!normalized.contains("web_fetch.preapproved_domains"));
    }

    #[test]
    fn validate_accepts_scoped_globs() {
        let cfg = PermissionsConfig {
            enabled: true,
            default_allow: vec![
                "Write(/project/**)".into(),
                "Bash(git *)".into(),
                "Bash(*.rs)".into(),
            ],
            mcp: HashMap::new(),
            project_proposal: None,
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_rejects_empty_pattern() {
        let cfg = PermissionsConfig {
            enabled: true,
            default_allow: vec!["ok".into(), String::new()],
            mcp: HashMap::new(),
            project_proposal: None,
        };
        let err = cfg.validate().expect_err("empty pattern must be rejected");
        assert!(err.contains("[1]"), "error must name the index: {err}");
        assert!(
            err.contains("empty pattern"),
            "error must mention emptiness: {err}"
        );
    }

    #[test]
    fn validate_rejects_unbounded_glob() {
        for unbounded in ["*", "**", "Bash(*)", "Write(**)"] {
            let cfg = PermissionsConfig {
                enabled: true,
                default_allow: vec![unbounded.into()],
                mcp: HashMap::new(),
                project_proposal: None,
            };
            let err = cfg.validate().expect_err("unbounded glob must be rejected");
            assert!(
                err.contains("unbounded"),
                "error must mention 'unbounded': {err}"
            );
        }
    }

    #[test]
    fn validate_rejects_control_characters() {
        let cfg = PermissionsConfig {
            enabled: true,
            default_allow: vec!["foo\u{1}bar".into()],
            mcp: HashMap::new(),
            project_proposal: None,
        };
        let err = cfg.validate().expect_err("control chars must be rejected");
        assert!(
            err.contains("control"),
            "error must mention 'control': {err}"
        );
    }

    #[test]
    fn validate_default_is_ok() {
        // Default is empty default_allow, so nothing to validate.
        assert!(PermissionsConfig::default().validate().is_ok());
    }

    // ── Crosslink #619: per-server MCP permissions ──────────────────────

    #[test]
    fn mcp_unrestricted_when_server_absent() {
        let cfg = PermissionsConfig::default();
        // No `mcp` entries → every server/tool is unrestricted at
        // this layer.
        assert!(cfg.mcp_tool_allowed("github", "create_issue"));
        assert!(cfg.mcp_tool_allowed("anything", "anything"));
    }

    #[test]
    fn mcp_allowlist_admits_exact_match_only() {
        let mut mcp = HashMap::new();
        mcp.insert(
            "github".into(),
            vec!["read_file".into(), "list_repos".into()],
        );
        let cfg = PermissionsConfig {
            enabled: true,
            default_allow: Vec::new(),
            mcp,
            project_proposal: None,
        };
        assert!(cfg.mcp_tool_allowed("github", "read_file"));
        assert!(cfg.mcp_tool_allowed("github", "list_repos"));
        assert!(!cfg.mcp_tool_allowed("github", "delete_file"));
        // Case-sensitive: capitalisation differences must not match.
        assert!(!cfg.mcp_tool_allowed("github", "Read_File"));
        // Unmentioned server is still wide-open.
        assert!(cfg.mcp_tool_allowed("railway", "deploy"));
    }

    #[test]
    fn mcp_empty_allowlist_denies_every_tool_on_server() {
        let mut mcp = HashMap::new();
        mcp.insert("blocked".into(), Vec::new());
        let cfg = PermissionsConfig {
            enabled: true,
            default_allow: Vec::new(),
            mcp,
            project_proposal: None,
        };
        assert!(!cfg.mcp_tool_allowed("blocked", "anything"));
        assert!(!cfg.mcp_tool_allowed("blocked", ""));
    }

    #[test]
    fn mcp_deserializes_from_yaml() {
        let yaml = r"
mcp:
  github:
    - read_file
    - list_repos
  blocked: []
";
        let cfg: PermissionsConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(cfg.mcp_tool_allowed("github", "read_file"));
        assert!(!cfg.mcp_tool_allowed("github", "delete_file"));
        assert!(!cfg.mcp_tool_allowed("blocked", "anything"));
        assert!(cfg.mcp_tool_allowed("absent", "anything"));
    }
}
