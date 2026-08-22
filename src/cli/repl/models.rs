use openclaudia::{config, providers};

/// Get static list of models for a provider (fallback when API unavailable)
pub fn get_available_models(provider: &str) -> Vec<&'static str> {
    providers::static_models_for_provider(provider).to_vec()
}

/// Fetch models dynamically from provider API (for OpenAI-compatible providers like LM Studio)
pub async fn fetch_dynamic_models(
    provider_config: &config::ProviderConfig,
    adapter: &dyn providers::ProviderAdapter,
) -> Option<Vec<String>> {
    if !adapter.supports_model_listing() {
        return None;
    }

    let extra_headers = provider_config.headers.clone();

    match providers::fetch_models_with_headers(
        &provider_config.base_url,
        provider_config.api_key.as_ref(),
        &extra_headers,
        adapter,
    )
    .await
    {
        Ok(models) => {
            let model_ids: Vec<String> = models.into_iter().map(|m| m.id).collect();
            if model_ids.is_empty() {
                None
            } else {
                Some(model_ids)
            }
        }
        Err(e) => {
            tracing::debug!("Failed to fetch models from API: {}", e);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::get_available_models;

    fn documented_models_for_heading(readme: &str, heading: &str) -> Vec<String> {
        let supported_models = readme
            .split_once("## Supported Models")
            .expect("README must document supported models")
            .1
            .split_once("## Behavioral Modes")
            .expect("supported models section must end before behavioral modes")
            .0;
        let heading_marker = format!("### {heading}");
        let section = supported_models
            .split_once(&heading_marker)
            .unwrap_or_else(|| panic!("README missing supported-model heading {heading:?}"))
            .1
            .split("### ")
            .next()
            .expect("provider model section");

        section
            .lines()
            .flat_map(|line| {
                let mut models = Vec::new();
                let mut rest = line;
                while let Some((_, after_open)) = rest.split_once('`') {
                    let Some((model, after_close)) = after_open.split_once('`') else {
                        break;
                    };
                    if !model.is_empty() {
                        models.push(model.to_string());
                    }
                    rest = after_close;
                }
                models
            })
            .collect()
    }

    #[test]
    fn readme_supported_models_match_static_repl_model_lists() {
        let readme = include_str!("../../../README.md");

        for (heading, provider) in [
            ("Anthropic", "anthropic"),
            ("OpenAI", "openai"),
            ("Google Gemini", "google"),
            ("DeepSeek", "deepseek"),
            ("Qwen", "qwen"),
            ("Z.AI (GLM)", "zai"),
            ("Kimi", "kimi"),
            ("MiniMax", "minimax"),
        ] {
            let documented = documented_models_for_heading(readme, heading);
            let static_models: Vec<String> = get_available_models(provider)
                .into_iter()
                .map(str::to_string)
                .collect();
            assert_eq!(
                documented, static_models,
                "README supported models for {heading} must match get_available_models({provider:?})"
            );
        }
    }

    #[test]
    fn static_model_lists_do_not_contain_duplicates() {
        for provider in [
            "anthropic",
            "openai",
            "google",
            "deepseek",
            "qwen",
            "zai",
            "kimi",
            "minimax",
        ] {
            let models = get_available_models(provider);
            let unique: BTreeSet<_> = models.iter().copied().collect();
            assert_eq!(
                models.len(),
                unique.len(),
                "static model list for {provider} must not contain duplicates"
            );
        }
    }

    #[test]
    fn provider_aliases_return_canonical_static_model_lists() {
        for (alias, canonical) in [
            ("gemini", "google"),
            ("glm", "zai"),
            ("zhipu", "zai"),
            ("alibaba", "qwen"),
            ("moonshot", "kimi"),
        ] {
            assert_eq!(
                get_available_models(alias),
                get_available_models(canonical),
                "static model list for alias {alias:?} must match canonical provider {canonical:?}"
            );
        }
    }
}
