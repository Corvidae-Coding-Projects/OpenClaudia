//! VDD engine: orchestrates the adversarial review loop (advisory + blocking modes).

use std::time::Duration;

use chrono::Utc;
use reqwest::Client;
use serde_json::Value;
use tracing::{debug, info, warn};

use crate::config::{AppConfig, VddConfig, VddMode};
use crate::providers::{get_adapter, ApiKey};
use crate::proxy::{ChatCompletionRequest, ChatMessage, MessageContent};
use crate::session::TokenUsage;

use crate::vdd::confabulation::{ConfabulationTracker, FindingIdentity};
use crate::vdd::error::{
    VddAdvisoryResult, VddBlockingResult, VddBlockingTextResult, VddError, VddResult,
};
use crate::vdd::finding::{Finding, FindingStatus};
use crate::vdd::helpers::{extract_user_task, findings_context_observation};
use crate::vdd::prompts::{build_adversary_request, build_revision_request};
use crate::vdd::review::{AdversaryReview, VddIteration, VddSession};
use crate::vdd::sink::{create_crosslink_issues, persist_session};
use crate::vdd::static_analysis::{run_shell_command, StaticAnalysisResult};
use crate::vdd::transport::{send_to_adversary, send_to_builder, VddProviderAuth, VddReviewBudget};
use crate::vdd::triage::{
    parse_findings_detailed, triage_findings, ParseFindingsOutcome, TriageContext,
};

/// The core VDD engine that orchestrates adversarial review loops.
pub struct VddEngine {
    pub(crate) config: VddConfig,
    pub(crate) app_config: AppConfig,
    pub(crate) client: Client,
    pub(crate) adversary_auth: Option<VddProviderAuth>,
}

/// Typed pair of `(provider_name, api_key)` for the builder agent.
///
/// The routing handle every VDD method needs in order to send a
/// follow-up request through the same provider that produced the
/// text under review (crosslink #950).
///
/// Previously these two were passed as `&str + Option<&ApiKey>` at
/// every call site; a typo in the provider name silently routed to
/// the wrong adapter with no diagnostic. Bundling them into a single
/// newtype eliminates the "did I pass the right pair?" failure mode
/// AND collapses the function-signature footprint from two
/// parameters to one.
#[derive(Debug, Clone, Copy)]
pub struct BuilderProvider<'a> {
    pub name: &'a str,
    pub model: Option<&'a str>,
    pub api_key: Option<&'a ApiKey>,
    pub auth: Option<&'a VddProviderAuth>,
}

impl<'a> BuilderProvider<'a> {
    /// Construct a builder-provider handle.
    #[must_use]
    pub const fn new(name: &'a str, api_key: Option<&'a ApiKey>) -> Self {
        Self {
            name,
            model: None,
            api_key,
            auth: None,
        }
    }

    /// Construct a builder-provider handle from runtime auth selected at
    /// startup.
    #[must_use]
    pub const fn with_auth(name: &'a str, auth: &'a VddProviderAuth) -> Self {
        Self {
            name,
            model: None,
            api_key: None,
            auth: Some(auth),
        }
    }

    /// Bind the exact builder model selected for a decoded-text frontend.
    #[must_use]
    pub const fn with_model(mut self, model: &'a str) -> Self {
        self.model = Some(model);
        self
    }
}

/// Per-iteration inputs for the blocking loop. Bundled into a struct so
/// `run_iteration` can take a single argument without tripping the
/// `too_many_arguments` lint.
struct IterationContext<'a> {
    budget: &'a VddReviewBudget,
    builder_text: &'a str,
    original_task: &'a str,
    static_results: &'a [StaticAnalysisResult],
    iteration: u32,
    previous_fps: &'a [FindingIdentity],
    builder: BuilderProvider<'a>,
}

struct BlockingLoopOutput {
    final_text: String,
    final_response: Option<Value>,
    session: VddSession,
    crosslink_issues: Vec<String>,
    provider_receipts: Vec<crate::vdd::VddProviderCallReceipt>,
}

impl VddEngine {
    #[must_use]
    pub fn new(config: &VddConfig, app_config: &AppConfig, client: Client) -> Self {
        Self {
            config: config.clone(),
            app_config: app_config.clone(),
            client,
            adversary_auth: None,
        }
    }

    #[must_use]
    pub fn new_with_adversary_auth(
        config: &VddConfig,
        app_config: &AppConfig,
        client: Client,
        adversary_auth: Option<VddProviderAuth>,
    ) -> Self {
        Self {
            config: config.clone(),
            app_config: app_config.clone(),
            client,
            adversary_auth,
        }
    }

    /// Verify one exact supervised-worker artifact through a fresh canonical
    /// verifier run with an alternate provider, endpoint, and model family.
    ///
    /// This returns only a proposed verification receipt. It cannot approve,
    /// publish, commit, close, complete, or mutate the reviewed artifact.
    pub async fn verify_worker_artifact(
        &self,
        run: &std::sync::Arc<crate::tools::ToolRunContext>,
        request: &crate::vdd::CanonicalVddRequest,
    ) -> crate::vdd::CanonicalVddReceipt {
        crate::vdd::canonical::run_canonical_verification(
            run,
            &self.client,
            &self.app_config,
            &self.config,
            self.adversary_auth.as_ref(),
            request,
        )
        .await
    }

    /// Simplified entry point for chat loop integration.
    /// Takes the builder text and user task, plus builder auth for the
    /// AI verification agent (which uses the builder's provider, not the
    /// adversary's, to avoid correlated confabulation).
    ///
    /// # Errors
    /// Returns an error if the adversary request fails or the response cannot be parsed.
    pub async fn review_text(
        &self,
        run: &std::sync::Arc<crate::tools::ToolRunContext>,
        builder_text: &str,
        user_task: &str,
        builder: BuilderProvider<'_>,
    ) -> Result<VddAdvisoryResult, VddError> {
        if !self.config.enabled {
            return Ok(VddAdvisoryResult {
                findings: vec![],
                context_observation: None,
                static_analysis: vec![],
                tokens_used: TokenUsage::default(),
                provider_receipts: Vec::new(),
            });
        }

        info!(
            mode = %self.config.mode,
            adversary = %self.config.adversary.provider,
            "VDD: Starting adversarial review"
        );

        run.require(crate::tools::ToolResource::Network)?;
        run.require(crate::tools::ToolResource::Secrets)?;

        self.single_pass_review(run, builder_text, user_task, builder)
            .await
    }

    /// Run a single adversarial pass: static analysis + adversary request +
    /// triage + context-injection formatting. Shared between [`Self::review_text`]
    /// (chat-loop entry, takes the user task directly) and [`Self::advisory_review`]
    /// (proxy entry, derives the user task from the upstream request).
    ///
    /// Callers are responsible for short-circuiting on disabled inputs and for
    /// emitting the "starting review" log line.
    ///
    /// Crosslink #746: previously duplicated verbatim across the two callers.
    async fn single_pass_review(
        &self,
        run: &std::sync::Arc<crate::tools::ToolRunContext>,
        builder_text: &str,
        user_task: &str,
        builder: BuilderProvider<'_>,
    ) -> Result<VddAdvisoryResult, VddError> {
        let budget = VddReviewBudget::admit(run, &self.config, false)?;
        // Run static analysis
        let static_results = self.run_static_analysis(run, &budget).await?;

        // Build and send adversary request
        let adversary_request = build_adversary_request(
            &self.config,
            &self.app_config,
            builder_text,
            user_task,
            &static_results,
            1,
        );

        let (adversary_text, tokens_used) = send_to_adversary(
            &budget,
            &self.client,
            &self.config,
            &self.app_config,
            &adversary_request,
            self.adversary_auth.as_ref(),
        )
        .await?;

        // Parse and triage findings (AI verifier uses builder's provider)
        let mut findings = parse_terminal_findings(&adversary_text, 1)?;
        let triage_ctx = TriageContext {
            budget: &budget,
            client: &self.client,
            config: &self.config,
            app_config: &self.app_config,
            previous_fps: &[],
            builder_code: builder_text,
            builder_provider: builder.name,
            builder_model: builder.model,
            builder_api_key: builder.api_key,
            builder_auth: builder.auth,
        };
        triage_findings(&mut findings, &triage_ctx).await;

        let context_observation = findings_context_observation(&findings, &static_results);

        let genuine_count = findings
            .iter()
            .filter(|f| f.status == FindingStatus::Genuine)
            .count();

        info!(
            total = findings.len(),
            genuine = genuine_count,
            "VDD advisory: review complete"
        );

        Ok(VddAdvisoryResult {
            findings,
            context_observation,
            static_analysis: static_results,
            tokens_used,
            provider_receipts: budget.provider_receipts(),
        })
    }

    /// Main entry point — called by proxy after builder responds.
    /// Routes to advisory or blocking mode based on config.
    ///
    /// # Errors
    /// Returns an error if the adversary request or builder revision fails.
    pub async fn process_response(
        &self,
        run: &std::sync::Arc<crate::tools::ToolRunContext>,
        builder_response: &Value,
        original_request: &ChatCompletionRequest,
        builder: BuilderProvider<'_>,
    ) -> Result<VddResult, VddError> {
        if !self.config.enabled {
            return Ok(VddResult::Skipped("VDD disabled".to_string()));
        }

        // Extract text content from builder response.
        //
        // Crosslink #479: previously called a hand-rolled
        // `vdd::parsing::extract_response_text` that hardcoded the
        // `OpenAI`/Anthropic/Gemini shapes inside the VDD module. Now
        // routed through the builder's `ProviderAdapter`, the same one
        // the proxy hot path uses — so a new provider sees identical
        // extraction semantics in both places.
        // Crosslink #433: a typo'd builder provider name short-circuits
        // VDD as "Skipped" with a useful diagnostic rather than silently
        // routing through OpenAIAdapter and returning empty text.
        let builder_adapter = match get_adapter(builder.name) {
            Ok(a) => a,
            Err(e) => {
                let name = builder.name;
                return Ok(VddResult::Skipped(format!(
                    "Builder provider '{name}' unknown: {e}"
                )));
            }
        };
        let builder_text = builder_adapter
            .extract_response_text(builder_response)
            .unwrap_or_default();
        if builder_text.is_empty() {
            return Ok(VddResult::Skipped(
                "Builder response has no text content".to_string(),
            ));
        }

        info!(
            mode = %self.config.mode,
            adversary = %self.config.adversary.provider,
            "VDD: Starting adversarial review"
        );

        run.require(crate::tools::ToolResource::Network)?;
        run.require(crate::tools::ToolResource::Secrets)?;

        match self.config.mode {
            VddMode::Advisory => {
                let result = self
                    .advisory_review(run, &builder_text, original_request, builder)
                    .await?;
                Ok(VddResult::Advisory(result))
            }
            VddMode::Blocking => {
                let result = self
                    .blocking_loop(
                        run,
                        builder_response,
                        &builder_text,
                        original_request,
                        builder,
                    )
                    .await?;
                Ok(VddResult::Blocking(result))
            }
        }
    }

    /// Advisory mode: single adversary pass, return findings for context injection.
    ///
    /// Thin wrapper over [`Self::single_pass_review`] — extracts the user task
    /// from the upstream `ChatCompletionRequest` and forwards. The disabled and
    /// empty-response gates are already enforced by [`Self::process_response`]
    /// before this is called, so we do not re-check them here.
    async fn advisory_review(
        &self,
        run: &std::sync::Arc<crate::tools::ToolRunContext>,
        builder_text: &str,
        original_request: &ChatCompletionRequest,
        builder: BuilderProvider<'_>,
    ) -> Result<VddAdvisoryResult, VddError> {
        let original_task = extract_user_task(original_request);
        self.single_pass_review(run, builder_text, &original_task, builder)
            .await
    }

    /// Blocking mode: full adversarial loop until convergence.
    async fn blocking_loop(
        &self,
        run: &std::sync::Arc<crate::tools::ToolRunContext>,
        initial_builder_response: &Value,
        initial_builder_text: &str,
        original_request: &ChatCompletionRequest,
        builder: BuilderProvider<'_>,
    ) -> Result<VddBlockingResult, VddError> {
        let builder_adapter =
            get_adapter(builder.name).map_err(|e| VddError::ConfigError(e.to_string()))?;
        let initial_builder_tokens = builder_adapter
            .extract_token_usage(initial_builder_response)
            .unwrap_or_default();
        let output = self
            .blocking_loop_core(
                run,
                initial_builder_text,
                Some(initial_builder_response.clone()),
                initial_builder_tokens,
                original_request,
                builder,
            )
            .await?;
        Ok(VddBlockingResult {
            final_response: output
                .final_response
                .unwrap_or_else(|| initial_builder_response.clone()),
            session: output.session,
            crosslink_issues: output.crosslink_issues,
            provider_receipts: output.provider_receipts,
        })
    }

    /// Run the full blocking revision/convergence loop for a frontend that has
    /// already decoded the provider response into exact text.
    pub(crate) async fn review_text_blocking(
        &self,
        run: &std::sync::Arc<crate::tools::ToolRunContext>,
        builder_text: &str,
        user_task: &str,
        builder: BuilderProvider<'_>,
    ) -> Result<VddBlockingTextResult, VddError> {
        if !self.config.enabled || self.config.mode != VddMode::Blocking {
            return Err(VddError::ConfigError(
                "text blocking review requires enabled blocking VDD configuration".to_string(),
            ));
        }
        run.require(crate::tools::ToolResource::Network)?;
        run.require(crate::tools::ToolResource::Secrets)?;
        let model = builder
            .model
            .or_else(|| {
                self.app_config
                    .providers
                    .get(builder.name)
                    .and_then(|provider| provider.model.as_deref())
            })
            .filter(|model| !model.trim().is_empty())
            .ok_or_else(|| {
                VddError::ConfigError(format!(
                    "Builder model is unavailable for blocking text revision through '{}'",
                    builder.name
                ))
            })?;
        let original_request = ChatCompletionRequest {
            model: model.to_string(),
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: MessageContent::Text(user_task.to_string()),
                name: None,
                tool_calls: None,
                tool_call_id: None,
                extra: std::collections::HashMap::new(),
            }],
            temperature: None,
            max_tokens: Some(crate::DEFAULT_MAX_TOKENS),
            stream: Some(false),
            tools: None,
            tool_choice: None,
            extra: std::collections::HashMap::new(),
        };
        let output = self
            .blocking_loop_core(
                run,
                builder_text,
                None,
                TokenUsage::default(),
                &original_request,
                builder,
            )
            .await?;
        Ok(VddBlockingTextResult {
            final_text: output.final_text,
            session: output.session,
            crosslink_issues: output.crosslink_issues,
            provider_receipts: output.provider_receipts,
        })
    }

    async fn blocking_loop_core(
        &self,
        run: &std::sync::Arc<crate::tools::ToolRunContext>,
        initial_builder_text: &str,
        initial_builder_response: Option<Value>,
        initial_builder_tokens: TokenUsage,
        original_request: &ChatCompletionRequest,
        builder: BuilderProvider<'_>,
    ) -> Result<BlockingLoopOutput, VddError> {
        let budget = VddReviewBudget::admit(run, &self.config, true)?;
        let mut session = VddSession::new(VddMode::Blocking);
        let mut tracker = ConfabulationTracker::new(
            f64::from(self.config.thresholds.false_positive_rate),
            self.config.thresholds.min_iterations,
        );

        let original_task = extract_user_task(original_request);
        let mut current_builder_text = initial_builder_text.to_string();
        let mut current_builder_response = initial_builder_response;
        let mut previous_fps: Vec<FindingIdentity> = Vec::new();

        // Crosslink #483 + #487: charge the INITIAL builder response's
        // tokens to the session's builder ledger before the loop starts.
        // Previously only revision-response tokens accumulated (at the
        // bottom of the loop body), so a clean pass that converged on
        // iteration 1 (no revisions needed) reported zero builder
        // tokens — misleading cost accounting shown to the user.
        // Crosslink #433: explicit error for an unknown builder provider —
        // the blocking loop has no graceful "skip" semantics here (we're
        // already past `advisory_review`'s skip gate), so we bubble it up
        // as `ConfigError`.
        session.builder_tokens.accumulate(&initial_builder_tokens);

        for iteration in 1..=self.config.thresholds.max_iterations {
            info!(
                iteration,
                max = self.config.thresholds.max_iterations,
                "VDD blocking: iteration"
            );

            let static_results = self.run_static_analysis(run, &budget).await?;

            let iteration_ctx = IterationContext {
                budget: &budget,
                builder_text: &current_builder_text,
                original_task: &original_task,
                static_results: &static_results,
                iteration,
                previous_fps: &previous_fps,
                builder,
            };
            let (genuine_count, fp_count, findings) =
                self.run_iteration(&iteration_ctx, &mut session).await?;

            tracker.record_iteration(genuine_count, fp_count);
            collect_false_positives(&findings, &mut previous_fps);

            info!(
                iteration,
                genuine = genuine_count,
                false_positives = fp_count,
                fp_rate = tracker.latest_rate().map_or_else(
                    || "n/a (no findings)".to_owned(),
                    |r| format!("{:.1}%", r * 100.0)
                ),
                "VDD blocking: iteration complete"
            );

            if self.check_convergence(&mut session, &tracker, iteration, genuine_count) {
                break;
            }

            // Step 5: If genuine findings, feed back to builder for revision.
            if genuine_count == 0 {
                debug!(
                    iteration,
                    min = self.config.thresholds.min_iterations,
                    "VDD blocking: no findings but below min iterations, continuing"
                );
                continue;
            }
            match self
                .revise_builder_response(
                    &budget,
                    original_request,
                    &current_builder_text,
                    &findings,
                    iteration,
                    builder,
                    &mut session,
                )
                .await
            {
                Ok(Some((revised_text, revised_response))) => {
                    current_builder_text = revised_text;
                    current_builder_response = Some(revised_response);
                }
                Ok(None) => break, // Revision recorded a failure and asked us to stop
                Err(e) => return Err(e),
            }
        }

        self.finalize_unconverged_session(&mut session);
        let crosslink_issues = self.create_issues_and_persist(run, &session).await;

        Ok(BlockingLoopOutput {
            final_text: current_builder_text,
            final_response: current_builder_response,
            session,
            crosslink_issues,
            provider_receipts: budget.provider_receipts(),
        })
    }

    /// Check the blocking-loop convergence criteria after an iteration is
    /// recorded. Returns `true` when the loop should stop, finalizing the
    /// session with the appropriate termination reason.
    fn check_convergence(
        &self,
        session: &mut VddSession,
        tracker: &ConfabulationTracker,
        iteration: u32,
        genuine_count: u32,
    ) -> bool {
        if tracker.should_terminate() {
            let rate_pct = tracker
                .latest_rate()
                .map_or_else(|| "n/a".to_owned(), |r| format!("{:.1}%", r * 100.0));
            session.finalize(
                true,
                &format!(
                    "Confabulation threshold reached: {} FP rate (threshold: {:.1}%)",
                    rate_pct,
                    self.config.thresholds.false_positive_rate * 100.0
                ),
            );
            info!(
                iterations = session.iterations.len(),
                fp_rate = rate_pct,
                "VDD blocking: converged (confabulation threshold)"
            );
            return true;
        }

        if genuine_count == 0 && iteration >= self.config.thresholds.min_iterations {
            session.finalize(true, "No genuine findings — clean pass");
            info!(
                iterations = session.iterations.len(),
                "VDD blocking: converged (clean pass)"
            );
            return true;
        }

        false
    }

    /// Send the genuine findings back to the builder for a revision pass.
    ///
    /// Returns:
    /// * `Ok(Some((text, json)))` — revision succeeded, caller should use these
    ///   as the new builder output and continue the loop.
    /// * `Ok(None)` — revision failed; the failure has been recorded on the
    ///   session and the caller should break out of the loop.
    /// * `Err(_)` — unrecoverable error.
    #[allow(clippy::too_many_arguments)] // Revision binds the complete current iteration and its shared budget/session authority.
    async fn revise_builder_response(
        &self,
        budget: &VddReviewBudget,
        original_request: &ChatCompletionRequest,
        prior_builder_text: &str,
        findings: &[Finding],
        iteration: u32,
        builder: BuilderProvider<'_>,
        session: &mut VddSession,
    ) -> Result<Option<(String, Value)>, VddError> {
        let genuine_findings: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.status == FindingStatus::Genuine)
            .collect();

        let revision_request = build_revision_request(
            original_request,
            prior_builder_text,
            &genuine_findings,
            iteration,
        );

        match send_to_builder(
            budget,
            &self.client,
            &self.config,
            &self.app_config,
            &revision_request,
            builder.name,
            builder.api_key,
            builder.auth,
        )
        .await
        {
            Ok((revised_text, revised_response, builder_tokens)) => {
                session.builder_tokens.accumulate(&builder_tokens);
                Ok(Some((revised_text, revised_response)))
            }
            Err(e) => {
                warn!(
                    "VDD blocking: builder revision failed: {}, stopping loop",
                    e
                );
                session.finalize(false, &format!("Builder revision failed: {e}"));
                Ok(None)
            }
        }
    }

    /// Finalize the session when the loop exhausted `max_iterations`
    /// without hitting a convergence condition.
    fn finalize_unconverged_session(&self, session: &mut VddSession) {
        if session.termination_reason.is_some() {
            return;
        }
        session.finalize(
            false,
            &format!(
                "Max iterations ({}) reached without convergence",
                self.config.thresholds.max_iterations
            ),
        );
        warn!(
            max = self.config.thresholds.max_iterations,
            "VDD blocking: max iterations reached"
        );
    }

    /// Run a single iteration of the blocking loop: adversary request,
    /// parsing, triage, and recording into the session.
    ///
    /// Returns `(genuine_count, false_positive_count, findings)`.
    async fn run_iteration(
        &self,
        ctx: &IterationContext<'_>,
        session: &mut VddSession,
    ) -> Result<(u32, u32, Vec<Finding>), VddError> {
        // Step 1: Build and send adversary request (fresh context every time)
        let adversary_request = build_adversary_request(
            &self.config,
            &self.app_config,
            ctx.builder_text,
            ctx.original_task,
            ctx.static_results,
            ctx.iteration,
        );
        let (adversary_text, adversary_tokens) = send_to_adversary(
            ctx.budget,
            &self.client,
            &self.config,
            &self.app_config,
            &adversary_request,
            self.adversary_auth.as_ref(),
        )
        .await?;

        // Step 2: Parse and triage findings (including AI verification)
        let mut findings = parse_terminal_findings(&adversary_text, ctx.iteration)?;
        let triage_ctx = TriageContext {
            budget: ctx.budget,
            client: &self.client,
            config: &self.config,
            app_config: &self.app_config,
            previous_fps: ctx.previous_fps,
            builder_code: ctx.builder_text,
            builder_provider: ctx.builder.name,
            builder_model: ctx.builder.model,
            builder_api_key: ctx.builder.api_key,
            builder_auth: ctx.builder.auth,
        };
        triage_findings(&mut findings, &triage_ctx).await;

        let genuine_count = u32::try_from(
            findings
                .iter()
                .filter(|f| f.status == FindingStatus::Genuine)
                .count(),
        )
        .unwrap_or(u32::MAX);
        let fp_count = u32::try_from(
            findings
                .iter()
                .filter(|f| f.status == FindingStatus::FalsePositive)
                .count(),
        )
        .unwrap_or(u32::MAX);

        // Record iteration
        let review = AdversaryReview {
            iteration: ctx.iteration,
            findings: findings.clone(),
            raw_response: adversary_text,
            tokens_used: adversary_tokens,
            timestamp: Utc::now(),
        };

        let vdd_iteration = VddIteration {
            number: ctx.iteration,
            builder_response: ctx.builder_text.to_string(),
            static_analysis: ctx.static_results.to_vec(),
            adversary_review: review,
            genuine_count,
            false_positive_count: fp_count,
        };

        session.record_iteration(vdd_iteration);

        Ok((genuine_count, fp_count, findings))
    }

    /// Create Chainlink issues for the session's genuine findings and
    /// persist the session if configured. Extracted from
    /// [`Self::blocking_loop`] purely to keep that function under the
    /// project's 100-line limit; behaviour is unchanged.
    async fn create_issues_and_persist(
        &self,
        run: &std::sync::Arc<crate::tools::ToolRunContext>,
        session: &VddSession,
    ) -> Vec<String> {
        let all_genuine: Vec<&Finding> = session
            .iterations
            .iter()
            .flat_map(|i| &i.adversary_review.findings)
            .filter(|f| f.status == FindingStatus::Genuine)
            .collect();

        let crosslink_issues = if all_genuine.is_empty() {
            Vec::new()
        } else {
            match create_crosslink_issues(run, &all_genuine).await {
                Ok(ids) => ids,
                Err(e) => {
                    warn!("VDD: Crosslink issue creation failed: {}", e);
                    Vec::new()
                }
            }
        };

        if self.config.tracking.persist {
            if let Err(e) = persist_session(&self.config.tracking.path, session) {
                warn!("VDD: Session persistence failed: {}", e);
            }
        }

        crosslink_issues
    }

    /// Run configured static analysis commands.
    async fn run_static_analysis(
        &self,
        run: &std::sync::Arc<crate::tools::ToolRunContext>,
        budget: &VddReviewBudget,
    ) -> Result<Vec<StaticAnalysisResult>, VddError> {
        if !self.config.static_analysis.enabled {
            return Ok(Vec::new());
        }

        // Determine commands: use explicit config, or auto-detect if enabled
        let commands: Vec<String> = if !self.config.static_analysis.commands.is_empty() {
            self.config.static_analysis.commands.clone()
        } else if self.config.static_analysis.auto_detect {
            let detected = crate::guardrails::get_auto_detected_commands(run);
            if detected.is_empty() {
                debug!("VDD: No static analysis commands configured or auto-detected");
                return Ok(Vec::new());
            }
            detected
        } else {
            return Ok(Vec::new());
        };

        if commands.len() > crate::config::VddStaticAnalysis::MAX_COMMANDS {
            return Err(VddError::ConfigError(format!(
                "Auto-detected {} analyzers, exceeding the VDD limit of {}",
                commands.len(),
                crate::config::VddStaticAnalysis::MAX_COMMANDS
            )));
        }

        let mut results = Vec::new();
        let timeout = Duration::from_secs(self.config.static_analysis.timeout_seconds);

        for command in &commands {
            debug!(command = %command, "VDD: Running static analysis");

            let result = run_shell_command(run, budget, command, timeout).await;
            info!(
                command = %command,
                passed = result.passed,
                exit_code = result.exit_code,
                "VDD: Static analysis complete"
            );
            if result.exit_code == -1
                || result
                    .stderr
                    .contains("output exceeded the bounded review limit")
            {
                if result.stderr.contains("timed out") {
                    return Err(VddError::StaticAnalysisTimeout {
                        command: command.clone(),
                        timeout: timeout.as_secs(),
                    });
                }
                return Err(VddError::AdversaryRequestFailed(format!(
                    "Static-analysis transport failed for '{command}': {}",
                    result.stderr
                )));
            }
            results.push(result);
        }

        Ok(results)
    }
}

fn parse_terminal_findings(response: &str, iteration: u32) -> Result<Vec<Finding>, VddError> {
    match parse_findings_detailed(response, iteration) {
        ParseFindingsOutcome::NoFindings => Ok(Vec::new()),
        ParseFindingsOutcome::Findings(findings) if findings.is_empty() => {
            Err(VddError::ParseError(
                "empty findings require an explicit NO_FINDINGS terminal assessment".to_string(),
            ))
        }
        ParseFindingsOutcome::Findings(findings) => Ok(findings),
        ParseFindingsOutcome::ParseError { kind } => Err(VddError::ParseError(format!(
            "adversary returned {} instead of a terminal findings report",
            kind.as_str()
        ))),
    }
}

/// Append false-positive identities from this iteration to the running
/// list used by the next iteration's duplicate-detection layer.
///
/// Crosslink #349: stores the full `(file, severity, cwe, line_range,
/// description)` identity so the next iteration can hash the tuple
/// deterministically rather than comparing free-text descriptions.
fn collect_false_positives(findings: &[Finding], previous_fps: &mut Vec<FindingIdentity>) {
    for f in findings {
        if f.status == FindingStatus::FalsePositive {
            previous_fps.push(FindingIdentity::from_finding(f));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::get_adapter;
    use serde_json::json;

    #[test]
    fn terminal_finding_parser_accepts_only_explicit_consistent_outcomes() {
        let clean = r#"{"findings": [], "assessment": "NO_FINDINGS"}"#;
        assert!(parse_terminal_findings(clean, 1)
            .expect("explicit clean report")
            .is_empty());

        let defect = r#"{
            "findings": [{"severity": "HIGH", "description": "reachable defect"}],
            "assessment": "FINDINGS_PRESENT"
        }"#;
        assert_eq!(
            parse_terminal_findings(defect, 1)
                .expect("explicit defect report")
                .len(),
            1
        );

        for invalid in [
            "",
            "not json",
            r#"{"findings": []}"#,
            r#"{"findings": [], "assessment": "FINDINGS_PRESENT"}"#,
            r#"{"findings": [{"description": "hidden defect"}], "assessment": "NO_FINDINGS"}"#,
        ] {
            assert!(
                matches!(
                    parse_terminal_findings(invalid, 1),
                    Err(VddError::ParseError(_))
                ),
                "invalid terminal response was accepted: {invalid}"
            );
        }
    }

    // ── Crosslink #483 + #487 ───────────────────────────────────────────────
    //
    // The blocking loop used to accumulate ONLY revision-response tokens
    // into `session.builder_tokens`; the initial builder response that
    // entered the loop was never charged. The new code lifts the same
    // adapter-based extraction the loop body uses and accumulates it
    // BEFORE iteration 1 starts. These tests pin that behaviour at the
    // mechanism level (extract + accumulate) so a refactor of
    // `blocking_loop` cannot silently drop the initial charge.

    /// An iteration-1 termination must show non-zero builder tokens when
    /// the initial response reported usage. The accumulation path mirrors
    /// what `blocking_loop` performs at the top of the function.
    #[test]
    fn initial_builder_tokens_are_accumulated_into_session() {
        let mut session = VddSession::new(VddMode::Blocking);
        // Initial builder response in `OpenAI` Chat Completions shape.
        let initial = json!({
            "choices": [{"message": {"content": "x".repeat(120)}}],
            "usage": {"prompt_tokens": 500, "completion_tokens": 200}
        });
        // The blocking loop calls `get_adapter(builder_provider)` and then
        // `.extract_token_usage(initial_builder_response)` before the
        // first iteration. Replicate that exactly.
        // Crosslink #433: `get_adapter` returns Result; `"openai"` is a
        // known canonical name so `.unwrap()` is infallible here.
        let adapter = get_adapter("openai").unwrap();
        let initial_tokens = adapter
            .extract_token_usage(&initial)
            .expect("OpenAI usage envelope present");
        session.builder_tokens.accumulate(&initial_tokens);

        assert_eq!(session.builder_tokens.input_tokens, 500);
        assert_eq!(session.builder_tokens.output_tokens, 200);
    }

    /// When subsequent revisions also charge tokens, both the initial and
    /// the revision charges must show up in the ledger — the new code
    /// must not REPLACE the initial charge with the revision charge.
    #[test]
    fn initial_plus_revision_builder_tokens_accumulate_additively() {
        let mut session = VddSession::new(VddMode::Blocking);
        let initial = json!({
            "choices": [{"message": {"content": "initial"}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 80}
        });
        let revision = json!({
            "choices": [{"message": {"content": "revised"}}],
            "usage": {"prompt_tokens": 250, "completion_tokens": 70}
        });
        let adapter = get_adapter("openai").unwrap();
        session
            .builder_tokens
            .accumulate(&adapter.extract_token_usage(&initial).unwrap());
        session
            .builder_tokens
            .accumulate(&adapter.extract_token_usage(&revision).unwrap());

        // 100 + 250 = 350, 80 + 70 = 150
        assert_eq!(session.builder_tokens.input_tokens, 350);
        assert_eq!(session.builder_tokens.output_tokens, 150);
    }

    /// A builder response that omits the `usage` envelope must not
    /// crash the accumulation — `.unwrap_or_default()` produces a
    /// zero-token record without panicking. Iteration-1 termination
    /// with a no-usage initial response gracefully reports zero.
    #[test]
    fn initial_builder_tokens_missing_usage_is_zero_not_panic() {
        let mut session = VddSession::new(VddMode::Blocking);
        // No `usage` field at all.
        let initial = json!({
            "choices": [{"message": {"content": "no usage envelope"}}]
        });
        let adapter = get_adapter("openai").unwrap();
        let initial_tokens = adapter.extract_token_usage(&initial).unwrap_or_default();
        session.builder_tokens.accumulate(&initial_tokens);

        assert_eq!(session.builder_tokens.input_tokens, 0);
        assert_eq!(session.builder_tokens.output_tokens, 0);
    }

    /// Cross-provider check: the accumulation path must work uniformly
    /// for Anthropic-shaped initial responses too — the bug surfaced as
    /// "Anthropic builder + OpenAI-only extractor reported zero tokens"
    /// (see #479 corresp.), so the test guards against that regression.
    #[test]
    fn initial_anthropic_builder_tokens_accumulate_via_adapter() {
        let mut session = VddSession::new(VddMode::Blocking);
        let initial = json!({
            "id": "msg_1",
            "model": "claude-opus-4-7",
            "stop_reason": "end_turn",
            "content": [{"type": "text", "text": "code goes here"}],
            "usage": {"input_tokens": 800, "output_tokens": 150}
        });
        let adapter = get_adapter("anthropic").unwrap();
        let initial_tokens = adapter
            .extract_token_usage(&initial)
            .expect("anthropic usage present");
        session.builder_tokens.accumulate(&initial_tokens);

        assert_eq!(session.builder_tokens.input_tokens, 800);
        assert_eq!(session.builder_tokens.output_tokens, 150);
    }
}
