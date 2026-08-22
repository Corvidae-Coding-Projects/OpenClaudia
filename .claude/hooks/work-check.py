#!/usr/bin/env python3
"""
PreToolUse hook that blocks Write|Edit|Bash unless a crosslink issue
is being actively worked on. Forces issue creation before code changes.

Also enforces comment discipline when comment_discipline is "required":
  - git commit requires a --kind plan comment on the active issue
  - crosslink issue close requires a --kind result comment
"""

import json
import sys
import os
import io
import sqlite3
import re

# Fix Windows encoding issues
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Add hooks directory to path for shared module import
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crosslink_config import (
    find_crosslink_dir,
    is_agent_context,
    load_config_merged,
    normalize_git_command,
    run_crosslink,
)

# Defaults — overridden by .crosslink/hook-config.json if present
DEFAULT_BLOCKED_GIT = [
    "git push",  "git rebase",
    "git reset", "git clean",
]

# Reduced block list for agents — they need push/commit/merge for their workflow
# but force-push, hard-reset, and clean remain dangerous even for agents.
DEFAULT_AGENT_BLOCKED_GIT = [
    "git push --force", "git push -f",
    "git reset --hard",
    "git clean -f", "git clean -fd", "git clean -fdx",
    "git checkout .", "git restore .",
]

# Git commands that are blocked UNLESS there is an active crosslink issue.
# This allows the /commit skill to work while still preventing unsolicited commits.
DEFAULT_GATED_GIT = [
    "git commit",
]

DEFAULT_ALLOWED_BASH = [
    "crosslink ",
    "git status", "git diff", "git log", "git branch", "git show",
    "jj log", "jj diff", "jj status", "jj show", "jj bookmark list",
    "cargo test", "cargo build", "cargo check", "cargo clippy", "cargo fmt",
    "npm test", "npm run", "npx ",
    "tsc", "node ", "python ",
    "ls", "dir", "pwd", "echo",
    # GitHub CLI and common read-only / infrastructure commands (#522)
    "gh ",
    "cat ", "head ", "tail ", "wc ",
    "grep ", "rg ", "find ", "sort ", "uniq ",
    "which ", "command ",
    "mktemp", "sleep ",
    "date", "env", "uname", "id ",
    "basename ", "dirname ", "realpath ", "stat ", "file ",
]


def load_config(crosslink_dir):
    """Load hook config from .crosslink/hook-config.json (with .local override), falling back to defaults.

    Returns (tracking_mode, blocked_git, gated_git, allowed_bash, is_agent, comment_discipline).
    tracking_mode is one of: "strict", "normal", "relaxed".
      strict  — block Write/Edit/Bash without an active issue
      normal  — remind (print warning) but don't block
      relaxed — no issue-tracking enforcement, only git blocks
    comment_discipline is one of: "required", "encouraged", "off".
      required  — block git commit without --kind plan, block issue close without --kind result
      encouraged — warn but don't block
      off — no comment enforcement
    """
    blocked = list(DEFAULT_BLOCKED_GIT)
    gated = list(DEFAULT_GATED_GIT)
    allowed = list(DEFAULT_ALLOWED_BASH)
    mode = "strict"
    discipline = "encouraged"
    is_agent = is_agent_context(crosslink_dir)

    config = load_config_merged(crosslink_dir)
    if not config:
        if is_agent:
            return "relaxed", list(DEFAULT_AGENT_BLOCKED_GIT), [], allowed, True, "off"
        return mode, blocked, gated, allowed, False, discipline

    if config.get("tracking_mode") in ("strict", "normal", "relaxed"):
        mode = config["tracking_mode"]
    if "blocked_git_commands" in config:
        blocked = config["blocked_git_commands"]
    if "gated_git_commands" in config:
        gated = config["gated_git_commands"]
    if "allowed_bash_prefixes" in config:
        allowed = config["allowed_bash_prefixes"]
    if config.get("comment_discipline") in ("required", "encouraged", "off"):
        discipline = config["comment_discipline"]

    # Apply agent overrides when running in an agent worktree
    if is_agent:
        overrides = config.get("agent_overrides", {})
        mode = overrides.get("tracking_mode", "relaxed")
        blocked = overrides.get("blocked_git_commands", list(DEFAULT_AGENT_BLOCKED_GIT))
        gated = overrides.get("gated_git_commands", [])
        discipline = overrides.get("comment_discipline", "off")
        # Merge agent lint/test commands into allowed prefixes (#495)
        for cmd in overrides.get("agent_lint_commands", []):
            if cmd not in allowed:
                allowed.append(cmd)
        for cmd in overrides.get("agent_test_commands", []):
            if cmd not in allowed:
                allowed.append(cmd)

    return mode, blocked, gated, allowed, is_agent, discipline


def _matches_command_list(command, cmd_list):
    """Check if a command matches any entry in the list (direct or chained).

    Normalizes git commands to strip global flags (-C, --git-dir, etc.)
    before matching, preventing bypass via 'git -C /path push'.
    """
    normalized = normalize_git_command(command)
    for entry in cmd_list:
        if normalized.startswith(entry):
            return True
    # Check chained commands (&&, ;, |) with normalization
    for sep in (" && ", " ; ", " | "):
        for part in command.split(sep):
            part = part.strip()
            if part:
                norm_part = normalize_git_command(part)
                for entry in cmd_list:
                    if norm_part.startswith(entry):
                        return True
    return False


def is_blocked_git(input_data, blocked_list):
    """Check if a Bash command is a permanently blocked git mutation."""
    command = input_data.get("tool_input", {}).get("command", "").strip()
    return _matches_command_list(command, blocked_list)


def is_gated_git(input_data, gated_list):
    """Check if a Bash command is a gated git command (allowed with active issue)."""
    command = input_data.get("tool_input", {}).get("command", "").strip()
    return _matches_command_list(command, gated_list)


def _is_single_command_allowed(command, allowed_list):
    """Check if a single (non-chained) command matches any allow-list prefix."""
    for prefix in allowed_list:
        if command.startswith(prefix):
            return True
    return False


def is_allowed_bash(input_data, allowed_list):
    """Check if a Bash command is on the allow list (read-only/infra).

    Splits on chain operators (&&, ;, |) and requires EVERY subcommand
    to match the allow list. A single non-allowed subcommand fails the
    entire chain, preventing bypass via 'allowed_cmd ; malicious_cmd'.
    """
    command = input_data.get("tool_input", {}).get("command", "").strip()
    if not command:
        return False

    # Split on all chain operators to get individual commands
    parts = [command]
    for sep in (" && ", " ; ", " | "):
        expanded = []
        for part in parts:
            expanded.extend(part.split(sep))
        parts = expanded

    # Every non-empty subcommand must be on the allow list
    for part in parts:
        part = part.strip()
        if part and not _is_single_command_allowed(part, allowed_list):
            return False
    return True


def is_claude_memory_path(input_data):
    """Check if a Write/Edit targets Claude Code's own memory/config directory (~/.claude/)."""
    tool_input = input_data.get("tool_input", {})
    file_path = tool_input.get("file_path") or tool_input.get("path", "")
    if not file_path:
        return False
    home = os.path.expanduser("~")
    claude_dir = os.path.join(home, ".claude")
    try:
        return os.path.normcase(os.path.abspath(file_path)).startswith(
            os.path.normcase(os.path.abspath(claude_dir))
        )
    except (ValueError, OSError):
        return False


def get_active_issue_id(crosslink_dir):
    """Get the numeric ID of the active work item from session status.

    Returns the issue ID as an integer, or None if no active issue.
    """
    status = run_crosslink(["session", "status", "--json"], crosslink_dir)
    if not status:
        return None
    try:
        data = json.loads(status)
        working_on = data.get("working_on")
        if working_on and working_on.get("id"):
            return int(working_on["id"])
    except (json.JSONDecodeError, ValueError, TypeError):
        pass
    return None


def issue_has_comment_kind(crosslink_dir, issue_id, kind):
    """Check if an issue has at least one comment of the given kind.

    Queries SQLite directly for speed (avoids spawning another process
    within the hook's 3-second timeout).
    """
    db_path = os.path.join(crosslink_dir, "issues.db")
    if not os.path.exists(db_path):
        return True  # No database — don't block
    try:
        conn = sqlite3.connect(db_path, timeout=1)
        cursor = conn.execute(
            "SELECT COUNT(*) FROM comments WHERE issue_id = ? AND kind = ?",
            (issue_id, kind),
        )
        count = cursor.fetchone()[0]
        conn.close()
        return count > 0
    except (sqlite3.Error, TypeError):
        return True  # DB error — don't block


def is_issue_close_command(input_data):
    """Check if a Bash command is `crosslink issue close` or `crosslink close`.

    Returns the issue ID string if found, or None.
    """
    command = input_data.get("tool_input", {}).get("command", "").strip()
    # Match: crosslink issue close <id> or crosslink close <id>
    # Also handle: crosslink -q issue close <id>, etc.
    m = re.search(r'crosslink\s+(?:-[qQ]\s+)?(?:issue\s+)?close\s+(\S+)', command)
    if m:
        issue_arg = m.group(1)
        # Skip flags like --no-changelog
        if issue_arg.startswith('-'):
            return None
        return issue_arg
    return None


def main():
    try:
        input_data = json.load(sys.stdin)
        tool_name = input_data.get('tool_name', '')
    except (json.JSONDecodeError, ValueError, TypeError):
        print("work-check: failed to parse stdin — blocking tool call (fail-closed)")
        sys.exit(2)

    # Normalize OpenClaudia's canonical registry names to Claude-compatible
    # lifecycle names before applying this compatibility workflow.
    tool_name = {
        'write_file': 'Write',
        'edit_file': 'Edit',
        'bash': 'Bash',
    }.get(tool_name, tool_name)

    # Only check on Write, Edit, Bash
    if tool_name not in ('Write', 'Edit', 'Bash'):
        sys.exit(0)

    # Allow Claude Code to manage its own memory/config in ~/.claude/
    if tool_name in ('Write', 'Edit') and is_claude_memory_path(input_data):
        sys.exit(0)

    crosslink_dir = find_crosslink_dir()
    tracking_mode, blocked_git, gated_git, allowed_bash, is_agent, comment_discipline = load_config(crosslink_dir)

    # PERMANENT BLOCK: git mutation commands are never allowed (all modes)
    if tool_name == 'Bash' and is_blocked_git(input_data, blocked_git):
        print(
            "MANDATORY COMPLIANCE — DO NOT ATTEMPT TO WORK AROUND THIS BLOCK.\n\n"
            "Git mutation commands (push, merge, rebase, reset, etc.) are "
            "PERMANENTLY FORBIDDEN. The human performs all git write operations.\n\n"
            "You MUST NOT:\n"
            "  - Retry this command\n"
            "  - Rewrite the command to achieve the same effect\n"
            "  - Use a different tool to perform git mutations\n"
            "  - Ask the user if you should bypass this restriction\n\n"
            "You MUST instead:\n"
            "  - Inform the user that this is a manual step for them\n"
            "  - Continue with your other work\n\n"
            "Read-only git commands (status, diff, log, show, branch) are allowed.\n\n"
            "--- INTERVENTION LOGGING ---\n"
            "Log this blocked action for the audit trail:\n"
            "  crosslink intervene <issue-id> \"Attempted: <command>\" "
            "--trigger tool_blocked --context \"<what you were trying to accomplish>\""
        )
        sys.exit(2)

    # GATED GIT: commands like `git commit` require an active crosslink issue
    if tool_name == 'Bash' and is_gated_git(input_data, gated_git):
        if not crosslink_dir:
            # No crosslink dir — allow through (no enforcement possible)
            sys.exit(0)
        status = run_crosslink(["session", "status"], crosslink_dir)
        if not (status and ("Working on: #" in status or "Working on: L" in status)):
            print(
                "Git commit requires an active crosslink issue.\n\n"
                "Create one first:\n"
                "  crosslink quick \"<describe the work>\" -p <priority> -l <label>\n\n"
                "Or pick an existing issue:\n"
                "  crosslink issue list -s open\n"
                "  crosslink session work <id>\n\n"
                "--- INTERVENTION LOGGING ---\n"
                "If a human redirected you here, log the intervention:\n"
                "  crosslink intervene <issue-id> \"Redirected to create issue before commit\" "
                "--trigger redirect --context \"Attempted git commit without active issue\""
            )
            sys.exit(2)

        # COMMENT DISCIPLINE: git commit requires --kind plan comment (#501)
        if comment_discipline in ("required", "encouraged"):
            issue_id = get_active_issue_id(crosslink_dir)
            if issue_id and not issue_has_comment_kind(crosslink_dir, issue_id, "plan"):
                msg = (
                    "Comment discipline: git commit requires a --kind plan comment "
                    "on the active issue before committing.\n\n"
                    "Add one now:\n"
                    "  crosslink issue comment {id} \"<your approach>\" --kind plan\n\n"
                    "This documents WHY the change was made, not just WHAT changed."
                ).format(id=issue_id)
                if comment_discipline == "required":
                    print(msg)
                    sys.exit(2)
                else:
                    print("Reminder: " + msg)

        sys.exit(0)

    # COMMENT DISCIPLINE: crosslink issue close requires --kind result comment (#501)
    if tool_name == 'Bash' and crosslink_dir and comment_discipline in ("required", "encouraged"):
        close_target = is_issue_close_command(input_data)
        if close_target:
            # Resolve the issue ID (could be numeric or L-prefixed)
            try:
                issue_id = int(close_target.lstrip('#'))
            except ValueError:
                # L-prefixed or other format — try via crosslink show
                show_output = run_crosslink(["issue", "show", close_target, "--json"], crosslink_dir)
                issue_id = None
                if show_output:
                    try:
                        issue_id = json.loads(show_output).get("id")
                    except (json.JSONDecodeError, TypeError):
                        pass

            if issue_id and not issue_has_comment_kind(crosslink_dir, issue_id, "result"):
                msg = (
                    "Comment discipline: closing an issue requires a --kind result "
                    "comment documenting what was delivered.\n\n"
                    "Add one now:\n"
                    "  crosslink issue comment {id} \"<what was delivered>\" --kind result\n\n"
                    "This creates the audit trail for the work that was done."
                ).format(id=issue_id)
                if comment_discipline == "required":
                    print(msg)
                    sys.exit(2)
                else:
                    print("Reminder: " + msg)

    # Allow read-only / infrastructure Bash commands through
    if tool_name == 'Bash' and is_allowed_bash(input_data, allowed_bash):
        sys.exit(0)

    # Relaxed mode: no issue-tracking enforcement
    if tracking_mode == "relaxed":
        sys.exit(0)

    if not crosslink_dir:
        sys.exit(0)

    # Fast path: check sentinel file written by `crosslink session work` / `quick` (#522).
    # Avoids spawning a subprocess (~100ms) on every non-allowlisted Bash call.
    sentinel = os.path.join(crosslink_dir, ".active-issue")
    if os.path.isfile(sentinel):
        try:
            with open(sentinel) as f:
                content = f.read().strip()
            if content:
                sys.exit(0)
        except OSError:
            pass  # Fall through to subprocess check

    # Slow path: sentinel missing or empty — fall back to session status subprocess
    status = run_crosslink(["session", "status"], crosslink_dir)
    if not status:
        # crosslink not available — don't block
        sys.exit(0)

    # If already working on an issue, allow
    if "Working on: #" in status or "Working on: L" in status:
        sys.exit(0)

    # No active work item — behavior depends on mode
    strict_msg = (
        "MANDATORY COMPLIANCE — DO NOT ATTEMPT TO WORK AROUND THIS BLOCK.\n\n"
        "You cannot Write, Edit, or run Bash commands without an active crosslink issue. "
        "This is a hard requirement enforced by the project, not a suggestion.\n\n"
        "You MUST NOT:\n"
        "  - Retry the same tool call hoping it will work\n"
        "  - Try alternative tools or approaches to bypass this check\n"
        "  - Proceed without creating an issue first\n"
        "You MUST do exactly this, right now, before anything else:\n\n"
        "  crosslink quick \"<describe what you are about to do>\" -p <priority> -l <label>\n\n"
        "This single command creates an issue AND sets it as your active work item. "
        "After running it, your tool calls will succeed.\n\n"
        "If an issue already exists for this work, use:\n"
        "  crosslink issue list -s open\n"
        "  crosslink session work <id>\n\n"
        "This is how the project tracks work. Comply, then continue.\n\n"
        "--- INTERVENTION LOGGING ---\n"
        "After creating the issue, log this intervention:\n"
        "  crosslink intervene <issue-id> \"Blocked: no active issue\" "
        "--trigger tool_blocked --context \"<what you were about to do>\""
    )

    normal_msg = (
        "Reminder: No active crosslink issue. You should create one before making changes.\n\n"
        "  crosslink quick \"<describe what you are about to do>\" -p <priority> -l <label>\n\n"
        "Or pick an existing issue:\n"
        "  crosslink issue list -s open\n"
        "  crosslink session work <id>"
    )

    if tracking_mode == "strict":
        print(strict_msg)
        sys.exit(2)
    else:
        # normal mode: remind but allow
        print(normal_msg)
        sys.exit(0)


if __name__ == "__main__":
    main()
