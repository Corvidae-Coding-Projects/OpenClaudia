/// Get a random tip to display at startup
pub fn get_random_tip() -> &'static str {
    const TIPS: &[&str] = &[
        "Type @ followed by a filepath to attach file contents to your message.",
        "Start a message with ! to run shell commands directly (e.g., !ls -la).",
        "Use /undo to revert the last message exchange.",
        "Use /redo to restore previously undone messages.",
        "Press Escape during streaming to cancel the AI response.",
        "Use /editor to compose long messages in your external editor.",
        "End a line with \\ to continue typing on the next line.",
        "Use /sessions to list and continue previous conversations.",
        "Use /export to save your conversation as a Markdown file.",
        "Use /compact to summarize old messages when context gets long.",
        "Use /models to see available models for your provider.",
        "Use /model <name> to switch models mid-conversation.",
        "Use /copy to copy the last AI response to your clipboard.",
        "Press Ctrl+R to search through your command history.",
        "Use /history to see all messages in the current session.",
        "Use /init to create a project configuration and skills directory.",
        "Use /review to review uncommitted git changes or compare branches.",
        "Use /status to see session info: model, token count, duration.",
        "Use /connect to configure API keys for different providers.",
        "Use /theme to preview and switch between color themes.",
        "Use /mode to toggle between Build (full access) and Plan (read-only) modes.",
        "Use /keybindings to see all configured keyboard shortcuts.",
        "Use /rename <title> to give your session a custom name.",
        "Quote paths with spaces: @\"path with spaces/file.txt\"",
        "Set up hooks in .openclaudia/hooks/ to customize agent behavior.",
        "Configure providers in .openclaudia/config.yaml or ~/.openclaudia/config.yaml.",
        "Use environment variables like ANTHROPIC_API_KEY for credentials.",
        "Dangerous shell commands will prompt for permission before running.",
        "Start a line with # to save a note without sending it to the AI.",
    ];

    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    #[allow(clippy::cast_possible_truncation)]
    // seed is a Unix timestamp in seconds; truncation on 32-bit is harmless for modulo indexing
    TIPS[(seed as usize) % TIPS.len()]
}
