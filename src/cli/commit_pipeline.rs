//! Generation-bound Git commit flow shared by `/commit` and `/commit-push-pr`.
//!
//! Production review and staging live in [`openclaudia::git_transaction`]. This
//! frontend module owns only message selection, explicit operator approval, and
//! the configured pre-commit gate.

use std::io::Write as _;

/// How the commit message is selected after the exact candidate is prepared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessagePolicy {
    /// Use the transaction's deterministic default message.
    Auto,
    /// Let the operator accept or edit the deterministic default.
    Prompt,
}

/// Options for one generation-bound commit attempt.
#[derive(Debug, Clone, Copy)]
pub struct CommitOptions {
    message_policy: MessagePolicy,
}

impl CommitOptions {
    /// `/commit` asks the operator to accept or edit the message.
    pub const fn interactive() -> Self {
        Self {
            message_policy: MessagePolicy::Prompt,
        }
    }

    /// `/commit-push-pr` uses the deterministic message while still requiring
    /// explicit approval of the exact review before the local commit.
    pub const fn automatic() -> Self {
        Self {
            message_policy: MessagePolicy::Auto,
        }
    }
}

/// Operator interaction used by the generation-bound commit flow.
pub trait UserPrompt {
    /// Resolve the commit message, or cancel.
    fn confirm_message(&mut self, default: &str) -> Option<String>;
    /// Approve the rendered exact paths, destination, message, and diff.
    fn confirm_review(&mut self, review: &str) -> bool;
}

/// Real stdin/stdout prompt implementation.
pub struct StdioPrompt;

impl UserPrompt for StdioPrompt {
    fn confirm_message(&mut self, default: &str) -> Option<String> {
        print!("\nCommit message: \x1b[36m{default}\x1b[0m\n[y/e(dit)/n] ");
        std::io::stdout().flush().ok();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).ok();
        match line.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" | "" => Some(default.to_string()),
            "e" | "edit" => {
                print!("Enter commit message: ");
                std::io::stdout().flush().ok();
                let mut custom = String::new();
                std::io::stdin().read_line(&mut custom).ok();
                let trimmed = custom.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            }
            _ => None,
        }
    }

    fn confirm_review(&mut self, review: &str) -> bool {
        println!("{review}");
        print!("Approve these exact paths and destination? [y/N] ");
        std::io::stdout().flush().ok();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).ok();
        matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
    }
}

/// Terminal state from the capability- and generation-bound production path.
#[derive(Debug)]
pub enum GenerationBoundCommitOutcome {
    Committed(Box<openclaudia::git_transaction::LocalCommitReceipt>),
    NothingToCommit,
    Cancelled(openclaudia::git_transaction::GitReviewCancellation),
}

/// Failure from the production commit path.
#[derive(Debug, thiserror::Error)]
pub enum GenerationBoundCommitError {
    #[error(transparent)]
    Git(#[from] openclaudia::git_transaction::GitTransactionError),
    #[error("git commit blocked by configured quality gates: {0}")]
    QualityGateBlocked(String),
}

/// Prepare, render, approve, revalidate, and publish one local commit bound to
/// the active run and workspace generations.
///
/// # Errors
///
/// Returns a typed Git transaction failure or a visible quality-gate refusal.
pub fn execute_generation_bound_commit<P, F>(
    run: &openclaudia::tools::ToolRunContext,
    prompt: &mut P,
    options: CommitOptions,
    mut pre_commit: F,
) -> Result<GenerationBoundCommitOutcome, GenerationBoundCommitError>
where
    P: UserPrompt,
    F: FnMut() -> Result<(), String>,
{
    let review = match openclaudia::git_transaction::prepare_commit_review(run) {
        Ok(review) => review,
        Err(openclaudia::git_transaction::GitTransactionError::NothingToCommit { .. }) => {
            return Ok(GenerationBoundCommitOutcome::NothingToCommit);
        }
        Err(error) => return Err(error.into()),
    };
    let default = review.default_message();
    let message = match options.message_policy {
        MessagePolicy::Auto => default,
        MessagePolicy::Prompt => match prompt.confirm_message(&default) {
            Some(message) => message,
            None => return Ok(GenerationBoundCommitOutcome::Cancelled(review.cancel())),
        },
    };
    let path_list = review
        .rendered_paths()
        .into_iter()
        .map(|path| format!("  - {path}"))
        .collect::<Vec<_>>()
        .join("\n");
    let display_message = openclaudia::tui::safety::sanitize_terminal_label(&message);
    let rendered = format!(
        "\n=== Exact Git Commit Review ===\n\nHEAD: {}\nDestination: {}\nCandidate tree: {}\nCommit message: {}\nPaths:\n{}\n\n{}",
        review.generation().head,
        review.destination(),
        review.candidate_tree(),
        display_message.as_str(),
        path_list,
        review.rendered_diff(),
    );
    if !prompt.confirm_review(&rendered) {
        return Ok(GenerationBoundCommitOutcome::Cancelled(review.cancel()));
    }
    let approval = review.approve(review.paths(), review.destination(), &message)?;
    pre_commit().map_err(GenerationBoundCommitError::QualityGateBlocked)?;
    let receipt = openclaudia::git_transaction::commit_approved_review(run, review, approval)?;
    Ok(GenerationBoundCommitOutcome::Committed(Box::new(receipt)))
}
