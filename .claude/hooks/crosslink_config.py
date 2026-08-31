#!/usr/bin/env python3
"""
Shared configuration and utility functions for crosslink Claude Code hooks.

This module is deployed to .claude/hooks/crosslink_config.py by `crosslink init`
and imported by the lifecycle hook scripts.
"""

import json
import os
import subprocess


def project_root_from_script():
    """Derive project root from this module's location (.claude/hooks/ -> project root)."""
    try:
        return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    except (NameError, OSError):
        return None


def get_project_root():
    """Get the project root directory.

    Prefers deriving from the hook script's own path (works even when cwd is a
    subdirectory), falling back to cwd.
    """
    root = project_root_from_script()
    if root and os.path.isdir(root):
        return root
    return os.getcwd()


def _resolve_main_repo_root(start_dir):
    """Resolve the main repository root when running inside a git worktree.

    Compares `git rev-parse --git-common-dir` with `--git-dir`. If they
    differ, we're in a worktree and the main repo root is the parent of
    git-common-dir. Returns None if not in a git repo.
    """
    try:
        common = subprocess.run(
            ["git", "-C", start_dir, "rev-parse", "--git-common-dir"],
            capture_output=True, text=True, timeout=3
        )
        git_dir = subprocess.run(
            ["git", "-C", start_dir, "rev-parse", "--git-dir"],
            capture_output=True, text=True, timeout=3
        )
        if common.returncode != 0 or git_dir.returncode != 0:
            return None

        common_path = os.path.realpath(
            common.stdout.strip() if os.path.isabs(common.stdout.strip())
            else os.path.join(start_dir, common.stdout.strip())
        )
        git_dir_path = os.path.realpath(
            git_dir.stdout.strip() if os.path.isabs(git_dir.stdout.strip())
            else os.path.join(start_dir, git_dir.stdout.strip())
        )

        if common_path != git_dir_path:
            # In a worktree — parent of git-common-dir is the main repo root
            return os.path.dirname(common_path)
        return start_dir
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


def find_crosslink_dir():
    """Find the .crosslink directory.

    Prefers the project root derived from the hook script's own path
    (reliable even when cwd is a subdirectory), falling back to walking
    up from cwd, then checking if we're in a git worktree and looking
    in the main repo root.
    """
    # Primary: resolve from script location
    root = project_root_from_script()
    if root:
        candidate = os.path.join(root, '.crosslink')
        if os.path.isdir(candidate):
            return candidate

    # Fallback: walk up from cwd
    current = os.getcwd()
    start = current
    for _ in range(10):
        candidate = os.path.join(current, '.crosslink')
        if os.path.isdir(candidate):
            return candidate
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent

    # Last resort: check if we're in a git worktree and look in the main repo
    main_root = _resolve_main_repo_root(start)
    if main_root:
        candidate = os.path.join(main_root, '.crosslink')
        if os.path.isdir(candidate):
            return candidate

    return None


def _merge_with_extend(base, override):
    """Merge *override* into *base* with array-extend support.

    Keys in *override* that start with ``+`` are treated as array-extend
    directives: their values are appended to the corresponding base array
    (with the ``+`` stripped from the key name).  For example::

        base:     {"allowed_bash_prefixes": ["ls", "pwd"]}
        override: {"+allowed_bash_prefixes": ["my-tool"]}
        result:   {"allowed_bash_prefixes": ["ls", "pwd", "my-tool"]}

    If the base has no matching key, the override value is used as-is.
    If the ``+``-prefixed value is not a list, it replaces like a normal key.
    Keys without a ``+`` prefix replace the base value (backward compatible).
    """
    for key, value in override.items():
        if key.startswith("+"):
            real_key = key[1:]
            if isinstance(value, list) and isinstance(base.get(real_key), list):
                base[real_key] = base[real_key] + value
            else:
                base[real_key] = value
        else:
            base[key] = value
    return base


def load_config_merged(crosslink_dir):
    """Load hook-config.json, then merge hook-config.local.json on top.

    Supports the ``+key`` convention for extending arrays rather than
    replacing them.  See ``_merge_with_extend`` for details.

    Returns the merged dict, or {} if neither file exists.
    """
    if not crosslink_dir:
        return {}

    config = {}
    config_path = os.path.join(crosslink_dir, "hook-config.json")
    if os.path.isfile(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config = json.load(f)
        except (json.JSONDecodeError, OSError):
            pass

    local_path = os.path.join(crosslink_dir, "hook-config.local.json")
    if os.path.isfile(local_path):
        try:
            with open(local_path, "r", encoding="utf-8") as f:
                local = json.load(f)
            _merge_with_extend(config, local)
        except (json.JSONDecodeError, OSError):
            pass

    return config


def load_tracking_mode(crosslink_dir):
    """Read tracking_mode from merged config. Defaults to 'strict'."""
    config = load_config_merged(crosslink_dir)
    mode = config.get("tracking_mode", "strict")
    if mode in ("strict", "normal", "relaxed"):
        return mode
    return "strict"


def find_crosslink_binary(crosslink_dir):
    """Find the crosslink binary, checking config, PATH, and common locations."""
    import shutil

    # 1. Check hook-config.json (+ local override) for explicit path
    config = load_config_merged(crosslink_dir)
    bin_path = config.get("crosslink_binary")
    if bin_path and os.path.isfile(bin_path) and os.access(bin_path, os.X_OK):
        return bin_path

    # 2. Check PATH
    found = shutil.which("crosslink")
    if found:
        return found

    # 3. Check common cargo install location
    home = os.path.expanduser("~")
    candidate = os.path.join(home, ".cargo", "bin", "crosslink")
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        return candidate

    # 4. Check relative to project root (dev builds)
    root = project_root_from_script()
    if root:
        for profile in ("release", "debug"):
            candidate = os.path.join(root, "crosslink", "target", profile, "crosslink")
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate

    return "crosslink"  # fallback to PATH lookup


def is_agent_context(crosslink_dir):
    """Check if we're running inside an agent worktree.

    Returns True if:
    1. .crosslink/agent.json exists (crosslink kickoff agent), OR
    2. CWD is inside a .claude/worktrees/ path (Claude Code sub-agent)

    Both types of agent get relaxed tracking mode so they can operate
    autonomously without active crosslink issues or gated git commits.
    """
    if not crosslink_dir:
        return False
    if os.path.isfile(os.path.join(crosslink_dir, "agent.json")):
        return True
    # Detect Claude Code sub-agent worktrees (Agent tool with isolation: "worktree")
    try:
        cwd = os.getcwd()
        if "/.claude/worktrees/" in cwd:
            return True
    except OSError:
        pass
    return False


def normalize_git_command(command):
    """Strip git global flags to extract the actual subcommand for matching.

    Git accepts flags like -C, --git-dir, --work-tree, -c before the
    subcommand. This normalizes 'git -C /path push' to 'git push' so
    that blocked/gated command matching can't be bypassed.
    """
    import shlex

    try:
        parts = shlex.split(command)
    except ValueError:
        return command

    if not parts or parts[0] != "git":
        return command

    i = 1
    while i < len(parts):
        # Flags that take a separate next argument
        if parts[i] in ("-C", "--git-dir", "--work-tree", "-c") and i + 1 < len(parts):
            i += 2
        # Flags with =value syntax
        elif (
            parts[i].startswith("--git-dir=")
            or parts[i].startswith("--work-tree=")
        ):
            i += 1
        else:
            break

    if i < len(parts):
        return "git " + " ".join(parts[i:])
    return command


_crosslink_bin = None


def run_crosslink(args, crosslink_dir=None):
    """Run a crosslink command and return output."""
    global _crosslink_bin
    if _crosslink_bin is None:
        _crosslink_bin = find_crosslink_binary(crosslink_dir)
    try:
        result = subprocess.run(
            [_crosslink_bin] + args,
            capture_output=True,
            text=True,
            timeout=3
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return None
