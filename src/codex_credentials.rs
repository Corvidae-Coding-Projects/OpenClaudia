//! Codex credential discovery for `OpenAI` auth.
//!
//! Codex stores login material in `$CODEX_HOME/auth.json` (or
//! `~/.codex/auth.json`) with the same logical shape as its open-source Rust
//! client. We read only enough of that shape to reuse supported credentials:
//! `OpenAI` API keys can feed the existing Chat Completions path, while `ChatGPT`
//! and Codex personal access tokens must use the Responses backend.

use base64::Engine as _;
use serde::Deserialize;
use serde_json::Value;
use std::path::{Path, PathBuf};

pub const CODEX_HOME_ENV_VAR: &str = "CODEX_HOME";
pub const CODEX_ACCESS_TOKEN_ENV_VAR: &str = "CODEX_ACCESS_TOKEN";
pub const CODEX_CHATGPT_BASE_URL: &str = "https://chatgpt.com/backend-api/codex";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodexAuthMode {
    ApiKey,
    Chatgpt,
    ChatgptAuthTokens,
    AgentIdentity,
    PersonalAccessToken,
    BedrockApiKey,
}

impl CodexAuthMode {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "api_key" | "apiKey" | "apikey" => Some(Self::ApiKey),
            "chatgpt" => Some(Self::Chatgpt),
            "chatgpt_auth_tokens" | "chatgptAuthTokens" => Some(Self::ChatgptAuthTokens),
            "agent_identity" | "agentIdentity" => Some(Self::AgentIdentity),
            "personal_access_token" | "personalAccessToken" => Some(Self::PersonalAccessToken),
            "bedrock_api_key" | "bedrockApiKey" => Some(Self::BedrockApiKey),
            _ => None,
        }
    }

    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::ApiKey => "OpenAI API key",
            Self::Chatgpt => "Codex ChatGPT login",
            Self::ChatgptAuthTokens => "external Codex ChatGPT tokens",
            Self::AgentIdentity => "Codex agent identity",
            Self::PersonalAccessToken => "Codex personal access token",
            Self::BedrockApiKey => "Codex Bedrock API key",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodexAuthSource {
    EnvAccessToken,
    AuthJson,
}

impl CodexAuthSource {
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::EnvAccessToken => CODEX_ACCESS_TOKEN_ENV_VAR,
            Self::AuthJson => "Codex auth.json",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CodexResponsesAuth {
    pub access_token: crate::secrets::OAuthToken,
    pub account_id: Option<String>,
    pub is_fedramp_account: bool,
    pub source: CodexAuthSource,
    pub mode: CodexAuthMode,
}

impl std::fmt::Debug for CodexResponsesAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodexResponsesAuth")
            .field("access_token", &"<redacted>")
            .field("account_id", &self.account_id)
            .field("is_fedramp_account", &self.is_fedramp_account)
            .field("source", &self.source)
            .field("mode", &self.mode)
            .finish()
    }
}

impl CodexResponsesAuth {
    /// Build the sensitive request headers for the Responses API.
    ///
    /// # Errors
    /// Returns an error if a caller-constructed account identifier is not a
    /// legal HTTP header value.
    pub fn headers(
        &self,
    ) -> Result<crate::secrets::SensitiveHeaders, crate::secrets::SensitiveHeaderError> {
        let mut headers = crate::secrets::SensitiveHeaders::new();
        headers.insert_header_bearer(reqwest::header::AUTHORIZATION, self.access_token.secret());
        headers.insert_static_literal(reqwest::header::ACCEPT, "text/event-stream");
        if let Some(account_id) = &self.account_id {
            headers.insert_literal("ChatGPT-Account-ID", account_id.clone())?;
        }
        if self.is_fedramp_account {
            headers.insert_static_literal(
                reqwest::header::HeaderName::from_static("x-openai-fedramp"),
                "true",
            );
        }
        Ok(headers)
    }

    #[must_use]
    pub fn label(&self) -> String {
        format!(
            "{} via {}",
            self.mode.display_name(),
            self.source.display_name()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodexAuthMaterial {
    ApiKey {
        api_key: crate::providers::ApiKey,
        source: CodexAuthSource,
    },
    Responses(CodexResponsesAuth),
    Unsupported {
        mode: CodexAuthMode,
        source: CodexAuthSource,
    },
}

impl CodexAuthMaterial {
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::ApiKey { source, .. } => {
                format!("OpenAI API key via {}", source.display_name())
            }
            Self::Responses(auth) => auth.label(),
            Self::Unsupported { mode, source } => {
                format!("{} via {}", mode.display_name(), source.display_name())
            }
        }
    }
}

#[derive(Deserialize)]
struct AuthDotJson {
    #[serde(default)]
    auth_mode: Option<String>,
    #[serde(
        default,
        rename = "OPENAI_API_KEY",
        deserialize_with = "deserialize_optional_api_key"
    )]
    openai_api_key: Option<crate::providers::ApiKey>,
    #[serde(default)]
    tokens: Option<TokenData>,
    #[serde(default)]
    agent_identity: Option<Value>,
    #[serde(default, deserialize_with = "deserialize_optional_oauth_token")]
    personal_access_token: Option<crate::secrets::OAuthToken>,
    #[serde(default)]
    bedrock_api_key: Option<Value>,
}

#[derive(Deserialize)]
struct TokenData {
    #[serde(default)]
    id_token: Option<IdToken>,
    #[serde(default, deserialize_with = "deserialize_optional_oauth_token")]
    access_token: Option<crate::secrets::OAuthToken>,
    #[serde(default)]
    account_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum IdToken {
    Raw(crate::secrets::OAuthToken),
    Object {
        #[serde(default)]
        raw_jwt: Option<crate::secrets::OAuthToken>,
        #[serde(default)]
        chatgpt_account_id: Option<String>,
        #[serde(default)]
        is_fedramp_account: Option<bool>,
    },
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct JwtClaims {
    account_id: Option<String>,
    is_fedramp_account: bool,
}

fn deserialize_optional_api_key<'de, D>(
    deserializer: D,
) -> Result<Option<crate::providers::ApiKey>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Option::<String>::deserialize(deserializer)?.map(zeroize::Zeroizing::new);
    let Some(raw) = raw else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    crate::providers::ApiKey::try_from_string(trimmed.to_string())
        .map(Some)
        .map_err(serde::de::Error::custom)
}

fn deserialize_optional_oauth_token<'de, D>(
    deserializer: D,
) -> Result<Option<crate::secrets::OAuthToken>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Option::<String>::deserialize(deserializer)?.map(zeroize::Zeroizing::new);
    let Some(raw) = raw else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    crate::secrets::OAuthToken::try_from_string(trimmed.to_string())
        .map(Some)
        .map_err(serde::de::Error::custom)
}

const fn raw_id_token(id_token: Option<&IdToken>) -> Option<&crate::secrets::OAuthToken> {
    match id_token {
        Some(IdToken::Raw(raw)) => Some(raw),
        Some(IdToken::Object { raw_jwt, .. }) => raw_jwt.as_ref(),
        None => None,
    }
}

fn id_token_claims(id_token: Option<&IdToken>) -> JwtClaims {
    let mut claims = raw_id_token(id_token)
        .and_then(parse_jwt_claims)
        .unwrap_or_default();
    if let Some(IdToken::Object {
        chatgpt_account_id,
        is_fedramp_account,
        ..
    }) = id_token
    {
        if claims.account_id.is_none() {
            claims.account_id.clone_from(chatgpt_account_id);
        }
        if !claims.is_fedramp_account {
            claims.is_fedramp_account = is_fedramp_account.unwrap_or(false);
        }
    }
    claims
}

fn parse_jwt_claims(token: &crate::secrets::OAuthToken) -> Option<JwtClaims> {
    token.expose(parse_jwt_claims_raw)
}

fn parse_jwt_claims_raw(token: &str) -> Option<JwtClaims> {
    let payload = token.split('.').nth(1)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let value: Value = serde_json::from_slice(&decoded).ok()?;
    let account_id = value
        .get("https://api.openai.com/auth.chatgpt_account_id")
        .or_else(|| value.get("chatgpt_account_id"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let is_fedramp_account = value
        .get("https://api.openai.com/auth.chatgpt_account_is_fedramp")
        .or_else(|| value.get("is_fedramp_account"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Some(JwtClaims {
        account_id,
        is_fedramp_account,
    })
}

fn resolved_mode(auth: &AuthDotJson) -> Option<CodexAuthMode> {
    if let Some(mode) = auth.auth_mode.as_deref().and_then(CodexAuthMode::parse) {
        return Some(mode);
    }
    if auth.personal_access_token.as_ref().is_some() {
        return Some(CodexAuthMode::PersonalAccessToken);
    }
    if auth.bedrock_api_key.is_some() {
        return Some(CodexAuthMode::BedrockApiKey);
    }
    if auth.openai_api_key.as_ref().is_some() {
        return Some(CodexAuthMode::ApiKey);
    }
    if auth.agent_identity.is_some() {
        return Some(CodexAuthMode::AgentIdentity);
    }
    if auth
        .tokens
        .as_ref()
        .is_some_and(|t| t.access_token.is_some())
    {
        return Some(CodexAuthMode::Chatgpt);
    }
    None
}

fn load_from_auth_json(auth: AuthDotJson) -> Option<CodexAuthMaterial> {
    let mode = resolved_mode(&auth)?;
    match mode {
        CodexAuthMode::ApiKey => {
            let Some(api_key) = auth.openai_api_key else {
                return Some(CodexAuthMaterial::Unsupported {
                    mode,
                    source: CodexAuthSource::AuthJson,
                });
            };
            Some(CodexAuthMaterial::ApiKey {
                api_key,
                source: CodexAuthSource::AuthJson,
            })
        }
        CodexAuthMode::Chatgpt | CodexAuthMode::ChatgptAuthTokens => {
            let Some(tokens) = auth.tokens else {
                return Some(CodexAuthMaterial::Unsupported {
                    mode,
                    source: CodexAuthSource::AuthJson,
                });
            };
            let Some(access_token) = tokens.access_token else {
                return Some(CodexAuthMaterial::Unsupported {
                    mode,
                    source: CodexAuthSource::AuthJson,
                });
            };
            let claims = id_token_claims(tokens.id_token.as_ref());
            let token_claims = parse_jwt_claims(&access_token).unwrap_or_default();
            Some(CodexAuthMaterial::Responses(CodexResponsesAuth {
                access_token,
                account_id: tokens
                    .account_id
                    .or(claims.account_id)
                    .or(token_claims.account_id),
                is_fedramp_account: claims.is_fedramp_account || token_claims.is_fedramp_account,
                source: CodexAuthSource::AuthJson,
                mode,
            }))
        }
        CodexAuthMode::PersonalAccessToken => {
            let Some(access_token) = auth.personal_access_token else {
                return Some(CodexAuthMaterial::Unsupported {
                    mode,
                    source: CodexAuthSource::AuthJson,
                });
            };
            let claims = parse_jwt_claims(&access_token).unwrap_or_default();
            Some(CodexAuthMaterial::Responses(CodexResponsesAuth {
                access_token,
                account_id: claims.account_id,
                is_fedramp_account: claims.is_fedramp_account,
                source: CodexAuthSource::AuthJson,
                mode,
            }))
        }
        CodexAuthMode::AgentIdentity | CodexAuthMode::BedrockApiKey => {
            Some(CodexAuthMaterial::Unsupported {
                mode,
                source: CodexAuthSource::AuthJson,
            })
        }
    }
}

#[must_use]
pub fn codex_home() -> Option<PathBuf> {
    std::env::var_os(CODEX_HOME_ENV_VAR)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|home| home.join(".codex")))
}

#[must_use]
pub fn auth_json_path() -> Option<PathBuf> {
    codex_home().map(|home| home.join("auth.json"))
}

#[must_use]
pub fn has_codex_auth_json() -> bool {
    auth_json_path().is_some_and(|path| path.is_file())
}

/// Load current Codex auth material from `CODEX_ACCESS_TOKEN` or auth.json.
///
/// This intentionally does not inspect OS keyrings or refresh tokens; those are
/// owned by Codex proper. Stale cached tokens surface as upstream auth errors.
///
/// # Errors
///
/// Returns an error if auth.json exists but cannot be read, is symlinked, or
/// cannot be parsed as Codex auth material.
pub fn load_codex_auth() -> Result<Option<CodexAuthMaterial>, String> {
    if let Ok(token) = std::env::var(CODEX_ACCESS_TOKEN_ENV_VAR) {
        let token = zeroize::Zeroizing::new(token);
        let token = token.trim();
        if !token.is_empty() {
            let access_token = crate::secrets::OAuthToken::try_from_string(token.to_string())
                .map_err(|error| format!("{CODEX_ACCESS_TOKEN_ENV_VAR} is invalid: {error}"))?;
            let claims = parse_jwt_claims(&access_token).unwrap_or_default();
            return Ok(Some(CodexAuthMaterial::Responses(CodexResponsesAuth {
                access_token,
                account_id: claims.account_id,
                is_fedramp_account: claims.is_fedramp_account,
                source: CodexAuthSource::EnvAccessToken,
                mode: CodexAuthMode::ChatgptAuthTokens,
            })));
        }
    }

    let Some(path) = auth_json_path() else {
        return Ok(None);
    };
    load_codex_auth_from_path(&path)
}

/// Load Codex auth material from a specific auth.json path.
///
/// # Errors
///
/// Returns an error if `path` is a symlink, cannot be read, or does not contain
/// valid JSON in the expected auth.json shape.
pub fn load_codex_auth_from_path(path: &Path) -> Result<Option<CodexAuthMaterial>, String> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(format!("failed to stat {}: {err}", path.display())),
    };
    if metadata.file_type().is_symlink() {
        return Err(format!("refusing to read symlinked {}", path.display()));
    }
    let raw = zeroize::Zeroizing::new(
        std::fs::read_to_string(path)
            .map_err(|err| format!("failed to read {}: {err}", path.display()))?,
    );
    let auth: AuthDotJson = serde_json::from_str(&raw)
        .map_err(|err| format!("failed to parse {}: {err}", path.display()))?;
    Ok(load_from_auth_json(auth))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn write_auth_json(value: &Value) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("auth.json");
        std::fs::write(&path, serde_json::to_vec(value).expect("json")).expect("write auth");
        (dir, path)
    }

    #[test]
    fn loads_api_key_from_auth_json() {
        let (_dir, path) = write_auth_json(&json!({
            "auth_mode": "api_key",
            "OPENAI_API_KEY": "sk-test"
        }));

        let auth = load_codex_auth_from_path(&path)
            .expect("load")
            .expect("auth");

        assert_eq!(
            auth,
            CodexAuthMaterial::ApiKey {
                api_key: crate::providers::ApiKey::try_from_string("sk-test".to_string())
                    .expect("key"),
                source: CodexAuthSource::AuthJson
            }
        );
    }

    #[test]
    fn auth_json_preserves_credential_whitespace_normalization() {
        let (_dir, path) = write_auth_json(&json!({
            "auth_mode": "api_key",
            "OPENAI_API_KEY": "  sk-trimmed-test  "
        }));
        let auth = load_codex_auth_from_path(&path)
            .expect("load")
            .expect("auth");
        let CodexAuthMaterial::ApiKey { api_key, .. } = auth else {
            panic!("expected API-key auth");
        };
        assert!(api_key.matches("sk-trimmed-test"));

        let (_dir, path) = write_auth_json(&json!({
            "auth_mode": "chatgpt",
            "tokens": {"access_token": "  access-trimmed-test  "}
        }));
        let auth = load_codex_auth_from_path(&path)
            .expect("load")
            .expect("auth");
        let CodexAuthMaterial::Responses(auth) = auth else {
            panic!("expected Responses auth");
        };
        assert!(auth.access_token.matches("access-trimmed-test"));
    }

    #[test]
    fn loads_chatgpt_tokens_for_responses_backend() {
        let (_dir, path) = write_auth_json(&json!({
            "auth_mode": "chatgpt",
            "tokens": {
                "access_token": "access-token",
                "account_id": "account-123",
                "id_token": {
                    "raw_jwt": null,
                    "is_fedramp_account": true
                }
            }
        }));

        let auth = load_codex_auth_from_path(&path)
            .expect("load")
            .expect("auth");

        let CodexAuthMaterial::Responses(auth) = auth else {
            panic!("expected responses auth");
        };
        assert!(auth.access_token.matches("access-token"));
        assert_eq!(auth.account_id.as_deref(), Some("account-123"));
        assert!(auth.is_fedramp_account);
        assert_eq!(auth.mode, CodexAuthMode::Chatgpt);
    }

    #[test]
    fn responses_headers_reject_invalid_account_id_without_panicking_or_leaking_token() {
        let secret = "s025-codex-token-4e2ac9";
        let auth = CodexResponsesAuth {
            access_token: crate::secrets::OAuthToken::try_from_string(secret.to_string())
                .expect("token"),
            account_id: Some("account\r\ninjected: value".to_string()),
            is_fedramp_account: false,
            source: CodexAuthSource::AuthJson,
            mode: CodexAuthMode::Chatgpt,
        };

        let error = auth
            .headers()
            .expect_err("invalid account identifier must fail during header construction");
        let rendered = error.to_string();
        assert!(
            !rendered.contains(secret),
            "header error leaked token: {rendered}"
        );
        assert!(!format!("{auth:?}").contains(secret));
    }

    #[test]
    fn refuses_symlinked_auth_json() {
        #[cfg(unix)]
        {
            let dir = tempfile::tempdir().expect("tempdir");
            let target = dir.path().join("target.json");
            let link = dir.path().join("auth.json");
            std::fs::write(&target, "{}").expect("write target");
            std::os::unix::fs::symlink(&target, &link).expect("symlink");

            let err = load_codex_auth_from_path(&link).unwrap_err();
            assert!(err.contains("refusing to read symlinked"));
        }
    }
}
