//! Shared git-commit pipeline used by `/commit` and `/commit-push-pr` (#476).
//!
//! Both slash commands inlined the same `status → stage → message → commit`
//! sequence, which drifted over time and re-declared `use std::process::Command`
//! at function scope. This module centralises the pipeline so:
//!
//! * `/commit` calls [`execute_commit_pipeline`] with `StagePolicy::Prompt` and
//!   `MessagePolicy::Prompt` (full interactive flow).
//! * `/commit-push-pr` calls it with `StagePolicy::AutoStage` and
//!   `MessagePolicy::Auto`, then layers push + `gh pr create` on top.
//!
//! The pipeline is parameterised on a [`GitRunner`] trait so tests can drive
//! it deterministically without shelling out to real git.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;

/// Absolute, PATH-independent location of the `git` binary for `/commit`.
///
/// The shared commit pipeline performs staging and commits on behalf of slash
/// commands. Resolve `git` once and invoke the absolute binary thereafter so a
/// later PATH mutation cannot redirect commit operations.
static GIT_BIN: LazyLock<Result<PathBuf, String>> =
    LazyLock::new(|| which::which("git").map_err(|e| format!("git binary not found on PATH: {e}")));

fn git_bin() -> Result<&'static Path, String> {
    match &*GIT_BIN {
        Ok(path) => Ok(path.as_path()),
        Err(msg) => Err(msg.clone()),
    }
}

fn git_command() -> Result<Command, String> {
    Ok(Command::new(git_bin()?))
}

/// Outcome of the shared commit pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitOutcome {
    /// Commit succeeded with the resolved commit message.
    Committed {
        /// The commit message that git actually used.
        message: String,
    },
    /// Working tree was clean — no staged or unstaged changes.
    NothingToCommit,
    /// User declined the stage prompt or the message prompt.
    Cancelled,
}

/// Errors that prevent the commit pipeline from completing.
#[derive(Debug, thiserror::Error)]
pub enum CommitError {
    /// We're not in a git working tree.
    #[error("Not inside a git repository.")]
    NotARepo,
    /// `git commit` itself failed (non-zero exit) or could not be invoked.
    /// The wrapped string is stderr (or the IO error message) verbatim.
    #[error("git commit failed: {0}")]
    CommitFailed(String),
    /// A configured quality gate refused the commit before `git commit` ran.
    #[error("git commit blocked by configured quality gates: {0}")]
    QualityGateBlocked(String),
}

/// How to handle unstaged changes when nothing is yet staged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StagePolicy {
    /// Prompt the user (`/commit` behaviour). Cancels on `n`/non-yes.
    Prompt,
    /// Silently `git add -A` (`/commit-push-pr` behaviour).
    AutoStage,
}

/// How the commit message is resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessagePolicy {
    /// Generate the default message and use it without prompting
    /// (`/commit-push-pr` behaviour).
    Auto,
    /// Show the default message and prompt y/e/n
    /// (`/commit` behaviour).
    Prompt,
}

/// Options driving a single pipeline invocation.
#[derive(Debug, Clone, Copy)]
pub struct CommitOptions {
    pub stage_policy: StagePolicy,
    pub message_policy: MessagePolicy,
}

impl CommitOptions {
    /// `/commit` defaults: interactive stage prompt + interactive message prompt.
    pub const fn interactive() -> Self {
        Self {
            stage_policy: StagePolicy::Prompt,
            message_policy: MessagePolicy::Prompt,
        }
    }

    /// `/commit-push-pr` defaults: auto-stage + auto-message.
    pub const fn automatic() -> Self {
        Self {
            stage_policy: StagePolicy::AutoStage,
            message_policy: MessagePolicy::Auto,
        }
    }
}

/// Abstraction over the git invocations the pipeline performs. Production
/// code uses [`RealGitRunner`]; tests use a recording fake.
pub trait GitRunner {
    fn is_inside_work_tree(&self) -> bool;
    fn has_staged_changes(&self) -> bool;
    fn has_unstaged_changes(&self) -> bool;
    /// `git add -A`. Best-effort; pipeline only consults `has_*` after.
    fn stage_all(&mut self);
    /// File paths in the staged set, one per line, no leading/trailing
    /// whitespace.
    fn staged_files(&self) -> Vec<String>;
    /// Returns the stderr on failure or stdout on success.
    fn commit(&mut self, message: &str) -> Result<String, String>;
}

/// User interaction surface — stdin prompts. Tests inject scripted answers.
pub trait UserPrompt {
    /// Stage prompt: returns true if user accepts staging.
    fn confirm_stage(&mut self, unstaged_summary: &str) -> bool;
    /// Message confirmation. Returns:
    /// * `Some(msg)` — use this message (default or edited)
    /// * `None`      — user cancelled.
    fn confirm_message(&mut self, default: &str) -> Option<String>;
}

/// Real implementation that shells out to `git`.
pub struct RealGitRunner;

impl GitRunner for RealGitRunner {
    fn is_inside_work_tree(&self) -> bool {
        git_command().is_ok_and(|mut cmd| {
            cmd.args(["rev-parse", "--is-inside-work-tree"])
                .output()
                .is_ok_and(|o| o.status.success())
        })
    }

    fn has_staged_changes(&self) -> bool {
        git_command().is_ok_and(|mut cmd| {
            cmd.args(["diff", "--cached", "--stat"])
                .output()
                .is_ok_and(|o| !o.stdout.is_empty())
        })
    }

    fn has_unstaged_changes(&self) -> bool {
        git_command().is_ok_and(|mut cmd| {
            cmd.args(["diff", "--stat"])
                .output()
                .is_ok_and(|o| !o.stdout.is_empty())
        })
    }

    fn stage_all(&mut self) {
        if let Ok(mut cmd) = git_command() {
            let _ = cmd.args(["add", "-A"]).output();
        }
    }

    fn staged_files(&self) -> Vec<String> {
        git_command()
            .and_then(|mut cmd| {
                cmd.args(["diff", "--cached", "--name-only"])
                    .output()
                    .map_err(|e| e.to_string())
            })
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn commit(&mut self, message: &str) -> Result<String, String> {
        let mut cmd = git_command()?;
        match cmd.args(["commit", "-m", message]).output() {
            Ok(o) if o.status.success() => {
                Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
            }
            Ok(o) => Err(String::from_utf8_lossy(&o.stderr).trim().to_string()),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// Real stdin/stdout prompts. Tests substitute a scripted prompt.
pub struct StdioPrompt;

impl UserPrompt for StdioPrompt {
    fn confirm_stage(&mut self, unstaged_summary: &str) -> bool {
        println!("\nUnstaged changes:");
        println!("{unstaged_summary}");
        print!("Stage all changes? [y/n] ");
        std::io::stdout().flush().ok();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).ok();
        line.trim().to_lowercase().starts_with('y')
    }

    fn confirm_message(&mut self, default: &str) -> Option<String> {
        print!("\nCommit message: \x1b[36m{default}\x1b[0m\n[y/e(dit)/n] ");
        std::io::stdout().flush().ok();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).ok();
        match line.trim().to_lowercase().as_str() {
            "y" | "yes" | "" => Some(default.to_string()),
            "e" | "edit" => {
                print!("Enter commit message: ");
                std::io::stdout().flush().ok();
                let mut custom = String::new();
                std::io::stdin().read_line(&mut custom).ok();
                let trimmed = custom.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            }
            _ => None,
        }
    }
}

/// Construct the default commit message from the staged file list.
pub fn default_message(staged_files: &[String]) -> String {
    if staged_files.len() == 1 {
        format!("Update {}", staged_files[0])
    } else {
        format!("Update {} files", staged_files.len())
    }
}

/// Shared `status → stage → message → commit` pipeline. Both `/commit` and
/// `/commit-push-pr` route through this function; the latter additionally
/// performs push + PR creation on a successful [`CommitOutcome::Committed`].
///
/// The pipeline never panics on git invocation failures; it returns
/// [`CommitError`] instead so callers can render errors consistently.
/// Execute the shared commit pipeline and call `pre_commit` at the last
/// reversible boundary, after staging/message selection but before Git can
/// create a commit.
pub fn execute_commit_pipeline<G, P, F>(
    git: &mut G,
    prompt: &mut P,
    opts: CommitOptions,
    mut pre_commit: F,
) -> Result<CommitOutcome, CommitError>
where
    G: GitRunner,
    P: UserPrompt,
    F: FnMut() -> Result<(), String>,
{
    if !git.is_inside_work_tree() {
        return Err(CommitError::NotARepo);
    }

    let has_staged = git.has_staged_changes();
    let has_unstaged = git.has_unstaged_changes();

    if !has_staged && !has_unstaged {
        return Ok(CommitOutcome::NothingToCommit);
    }

    // Stage step — only runs if nothing is staged but there are unstaged
    // changes. Policy decides whether to ask first.
    if !has_staged {
        match opts.stage_policy {
            StagePolicy::Prompt => {
                if !prompt.confirm_stage("(see git diff --stat)") {
                    return Ok(CommitOutcome::Cancelled);
                }
                git.stage_all();
            }
            StagePolicy::AutoStage => {
                git.stage_all();
            }
        }
    }

    let files = git.staged_files();
    if files.is_empty() {
        // Staging was attempted but produced no staged set (e.g. all files
        // were already deleted/ignored). Treat as nothing-to-commit so the
        // caller doesn't fabricate a meaningless "Update 0 files" commit.
        return Ok(CommitOutcome::NothingToCommit);
    }

    let default = default_message(&files);
    let resolved = match opts.message_policy {
        MessagePolicy::Auto => default,
        MessagePolicy::Prompt => match prompt.confirm_message(&default) {
            Some(msg) => msg,
            None => return Ok(CommitOutcome::Cancelled),
        },
    };

    pre_commit().map_err(CommitError::QualityGateBlocked)?;
    match git.commit(&resolved) {
        Ok(_stdout) => Ok(CommitOutcome::Committed { message: resolved }),
        Err(stderr) => Err(CommitError::CommitFailed(stderr)),
    }
}

#[cfg(test)]
mod test_support {
    //! Recording fakes for tests inside this crate.
    use super::{GitRunner, UserPrompt};
    use std::cell::RefCell;

    /// Records every interaction so tests can assert call order.
    #[derive(Default)]
    pub struct FakeGit {
        pub in_repo: bool,
        pub staged: bool,
        pub unstaged: bool,
        pub files: Vec<String>,
        pub commit_result: Option<Result<String, String>>,
        pub log: RefCell<Vec<String>>,
    }

    impl FakeGit {
        pub fn new() -> Self {
            Self {
                in_repo: true,
                staged: false,
                unstaged: false,
                files: Vec::new(),
                commit_result: Some(Ok("ok".into())),
                log: RefCell::new(Vec::new()),
            }
        }
    }

    impl GitRunner for FakeGit {
        fn is_inside_work_tree(&self) -> bool {
            self.log.borrow_mut().push("is_inside_work_tree".into());
            self.in_repo
        }
        fn has_staged_changes(&self) -> bool {
            self.log.borrow_mut().push("has_staged_changes".into());
            self.staged
        }
        fn has_unstaged_changes(&self) -> bool {
            self.log.borrow_mut().push("has_unstaged_changes".into());
            self.unstaged
        }
        fn stage_all(&mut self) {
            self.log.borrow_mut().push("stage_all".into());
            // Simulate staging: now staged, no longer unstaged.
            self.staged = true;
            self.unstaged = false;
        }
        fn staged_files(&self) -> Vec<String> {
            self.log.borrow_mut().push("staged_files".into());
            self.files.clone()
        }
        fn commit(&mut self, message: &str) -> Result<String, String> {
            self.log.borrow_mut().push(format!("commit:{message}"));
            self.commit_result
                .clone()
                .unwrap_or_else(|| Ok("ok".into()))
        }
    }

    pub struct ScriptedPrompt {
        pub stage_answer: bool,
        pub message_answer: Option<String>,
        pub log: RefCell<Vec<String>>,
    }

    impl ScriptedPrompt {
        pub fn accepting() -> Self {
            Self {
                stage_answer: true,
                message_answer: Some("default".into()),
                log: RefCell::new(Vec::new()),
            }
        }
    }

    impl UserPrompt for ScriptedPrompt {
        fn confirm_stage(&mut self, _summary: &str) -> bool {
            self.log.borrow_mut().push("confirm_stage".into());
            self.stage_answer
        }
        fn confirm_message(&mut self, default: &str) -> Option<String> {
            self.log
                .borrow_mut()
                .push(format!("confirm_message:{default}"));
            // The prompt impl returns the *resolved* string. If the test
            // supplied a literal "default" marker we echo back the default.
            match &self.message_answer {
                Some(s) if s == "default" => Some(default.to_string()),
                Some(s) => Some(s.clone()),
                None => None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{FakeGit, ScriptedPrompt};
    use super::*;

    #[test]
    fn default_message_single_file() {
        assert_eq!(default_message(&["a.rs".into()]), "Update a.rs");
    }

    #[test]
    fn default_message_multi_file() {
        let files = vec!["a.rs".into(), "b.rs".into()];
        assert_eq!(default_message(&files), "Update 2 files");
    }

    /// Mandate test #1: helper with a normal message produces a successful
    /// `CommitOutcome::Committed` whose message matches the staged set.
    #[test]
    fn helper_normal_message_returns_committed() {
        let mut git = FakeGit::new();
        git.staged = true;
        git.files = vec!["src/lib.rs".into()];
        let mut prompt = ScriptedPrompt::accepting();

        let outcome =
            execute_commit_pipeline(&mut git, &mut prompt, CommitOptions::automatic(), || Ok(()))
                .unwrap();

        assert_eq!(
            outcome,
            CommitOutcome::Committed {
                message: "Update src/lib.rs".into()
            }
        );
        assert!(git
            .log
            .borrow()
            .iter()
            .any(|e| e == "commit:Update src/lib.rs"));
    }

    /// Mandate test #2: empty working tree returns `NothingToCommit`
    /// without invoking the commit step.
    #[test]
    fn helper_empty_tree_returns_nothing_to_commit() {
        let mut git = FakeGit::new();
        // staged=false, unstaged=false
        let mut prompt = ScriptedPrompt::accepting();

        let outcome =
            execute_commit_pipeline(&mut git, &mut prompt, CommitOptions::interactive(), || {
                Ok(())
            })
            .unwrap();

        assert_eq!(outcome, CommitOutcome::NothingToCommit);
        assert!(!git.log.borrow().iter().any(|e| e.starts_with("commit:")));
        assert!(!git.log.borrow().iter().any(|e| e == "stage_all"));
    }

    /// Mandate test #3: both /commit (interactive) and /commit-push-pr
    /// (automatic) entries flow through the same helper. We assert this by
    /// running both code paths over the same `FakeGit` setup and verifying
    /// the commit step fires with the same default-derived message.
    #[test]
    fn both_seams_invoke_shared_helper() {
        // /commit-push-pr seam — auto-stage, auto-message.
        let mut git_auto = FakeGit::new();
        git_auto.unstaged = true;
        git_auto.files = vec!["a.rs".into(), "b.rs".into()];
        let mut prompt_auto = ScriptedPrompt::accepting();
        let auto_outcome = execute_commit_pipeline(
            &mut git_auto,
            &mut prompt_auto,
            CommitOptions::automatic(),
            || Ok(()),
        )
        .unwrap();

        // /commit seam — interactive stage prompt, interactive message.
        let mut git_interactive = FakeGit::new();
        git_interactive.unstaged = true;
        git_interactive.files = vec!["a.rs".into(), "b.rs".into()];
        let mut prompt_interactive = ScriptedPrompt::accepting();
        let interactive_outcome = execute_commit_pipeline(
            &mut git_interactive,
            &mut prompt_interactive,
            CommitOptions::interactive(),
            || Ok(()),
        )
        .unwrap();

        // Same default message construction → same commit message.
        let expected_msg = "Update 2 files".to_string();
        assert_eq!(
            auto_outcome,
            CommitOutcome::Committed {
                message: expected_msg.clone()
            }
        );
        assert_eq!(
            interactive_outcome,
            CommitOutcome::Committed {
                message: expected_msg.clone()
            }
        );

        // Both seams must have invoked the commit step exactly once with the
        // shared message — proves they share the helper.
        let auto_commits: Vec<_> = git_auto
            .log
            .borrow()
            .iter()
            .filter(|e| e.starts_with("commit:"))
            .cloned()
            .collect();
        let interactive_commits: Vec<_> = git_interactive
            .log
            .borrow()
            .iter()
            .filter(|e| e.starts_with("commit:"))
            .cloned()
            .collect();
        assert_eq!(auto_commits, vec![format!("commit:{expected_msg}")]);
        assert_eq!(interactive_commits, vec![format!("commit:{expected_msg}")]);

        // And the interactive seam must have asked before staging, while
        // the auto seam must not have.
        assert!(prompt_interactive
            .log
            .borrow()
            .iter()
            .any(|e| e == "confirm_stage"));
        assert!(!prompt_auto
            .log
            .borrow()
            .iter()
            .any(|e| e == "confirm_stage"));
    }

    #[test]
    fn interactive_cancel_on_stage_prompt_returns_cancelled() {
        let mut git = FakeGit::new();
        git.unstaged = true;
        git.files = vec!["a.rs".into()];
        let mut prompt = ScriptedPrompt {
            stage_answer: false,
            message_answer: None,
            log: std::cell::RefCell::new(Vec::new()),
        };
        let outcome =
            execute_commit_pipeline(&mut git, &mut prompt, CommitOptions::interactive(), || {
                Ok(())
            })
            .unwrap();
        assert_eq!(outcome, CommitOutcome::Cancelled);
        assert!(!git.log.borrow().iter().any(|e| e.starts_with("commit:")));
    }

    #[test]
    fn interactive_cancel_on_message_prompt_returns_cancelled() {
        let mut git = FakeGit::new();
        git.staged = true;
        git.files = vec!["a.rs".into()];
        let mut prompt = ScriptedPrompt {
            stage_answer: true,
            message_answer: None,
            log: std::cell::RefCell::new(Vec::new()),
        };
        let outcome =
            execute_commit_pipeline(&mut git, &mut prompt, CommitOptions::interactive(), || {
                Ok(())
            })
            .unwrap();
        assert_eq!(outcome, CommitOutcome::Cancelled);
        assert!(!git.log.borrow().iter().any(|e| e.starts_with("commit:")));
    }

    #[test]
    fn not_a_repo_returns_error() {
        let mut git = FakeGit::new();
        git.in_repo = false;
        let mut prompt = ScriptedPrompt::accepting();
        let err =
            execute_commit_pipeline(&mut git, &mut prompt, CommitOptions::automatic(), || Ok(()))
                .unwrap_err();
        assert!(matches!(err, CommitError::NotARepo));
    }

    #[test]
    fn commit_failure_propagates_as_error() {
        let mut git = FakeGit::new();
        git.staged = true;
        git.files = vec!["a.rs".into()];
        git.commit_result = Some(Err("pre-commit hook failed".into()));
        let mut prompt = ScriptedPrompt::accepting();
        let err =
            execute_commit_pipeline(&mut git, &mut prompt, CommitOptions::automatic(), || Ok(()))
                .unwrap_err();
        match err {
            CommitError::CommitFailed(msg) => assert!(msg.contains("pre-commit")),
            CommitError::NotARepo => panic!("expected CommitFailed, got NotARepo"),
            CommitError::QualityGateBlocked(reason) => {
                panic!("expected CommitFailed, got quality-gate block: {reason}")
            }
        }
    }

    #[test]
    fn configured_gate_runs_at_last_boundary_and_prevents_commit() {
        let mut git = FakeGit::new();
        git.staged = true;
        git.files = vec!["a.rs".into()];
        let mut prompt = ScriptedPrompt::accepting();
        let mut gate_calls = 0_u8;

        let err =
            execute_commit_pipeline(&mut git, &mut prompt, CommitOptions::automatic(), || {
                gate_calls += 1;
                Err("tests failed".to_string())
            })
            .unwrap_err();

        assert!(matches!(
            err,
            CommitError::QualityGateBlocked(reason) if reason == "tests failed"
        ));
        assert_eq!(gate_calls, 1);
        assert!(!git.log.borrow().iter().any(|e| e.starts_with("commit:")));
    }

    #[test]
    fn real_git_runner_uses_resolved_binary_path() {
        let git = git_bin().expect("commit pipeline tests require git on PATH");
        assert!(
            git.is_absolute(),
            "git_bin must resolve git to an absolute path, got {}",
            git.display()
        );

        let src = include_str!("commit_pipeline.rs");
        let cfg_test = src
            .find("#[cfg(test)]")
            .expect("test module marker must be present");
        let production = &src[..cfg_test];

        for (idx, raw_line) in production.lines().enumerate() {
            let code = raw_line.split("//").next().unwrap_or("");
            assert!(
                !code.contains("Command::new(\"git\")"),
                "production commit pipeline must not invoke bare git; line {n}: {raw_line}",
                n = idx + 1,
            );
        }
    }
}
