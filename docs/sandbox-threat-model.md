# Agent sandbox threat model

## Security objective

Repository content, model output, hook configuration, language-server
configuration, analyzers, quality gates, and untrusted MCP configuration are
hostile inputs. An agent-operated path must not read or modify data outside
its immutable session capabilities, reach host networking or IPC, inherit host
credentials, or leave processes behind.

Permission prompts remain useful defense in depth, but they are not the
isolation boundary. The boundary is formed by per-session filesystem
capabilities plus the named subprocess sandbox profiles.

## Trust classes

- **Agent-operated:** Bash, background Bash, file/list/glob/grep/notebook
  tools, ACP-local tools, repository hooks, LSPs, analyzers, document parsers,
  quality gates, and Git worktree tools. These use capability-safe filesystem
  primitives or a named sandbox profile.
- **Brokered:** provider HTTP, web/search, and remote MCP HTTP. These execute
  outside the subprocess sandbox and enforce URL/SSRF, credential, timeout,
  and response-size policies at their own boundary.
- **Trusted host:** interactive TUI `!` commands, browser opening, plugin
  administration, CLI Git/GitHub operations, and transcript metadata. They
  are reachable only from user-operated surfaces, not the model tool
  registry. Repository MCP servers require an exact host-startup trust grant
  even though their stdio process is still sandboxed.

## Session capabilities

A session pins its canonical project root, working directory, read-only and
read-write roots, private temporary directory, owner ID, exact environment
grants, denied project paths, and network policy. The context is immutable
after first registration. Background process lookup, signaling, cancellation,
and cleanup are owner-bound.

On Unix, root directories are opened when the context is created. Linux file
operations use `openat2` with `RESOLVE_BENEATH`, `RESOLVE_NO_MAGICLINKS`, and
`RESOLVE_NO_SYMLINKS`. macOS uses an `openat`/`O_NOFOLLOW`
descriptor-relative component walk. Symlinks are intentionally unsupported,
including symlinks whose targets remain inside a granted root. This policy is
stricter and easier to enforce atomically. Windows file tools fail closed
until a reparse-point-safe handle backend exists.

Linux subprocess capability roots and validated Git metadata are also passed
to Bubblewrap as pinned descriptors (`--bind-fd`/`--ro-bind-fd`), not reopened
by pathname after validation. Only those descriptors and the seccomp-filter
descriptor survive the launcher's inherited-file-descriptor closure.

The project is read-write by default. This includes `.env`, local test keys,
fixtures, and generated credentials stored in the repository. `.openclaudia`
and `.claude` are always masked. Operators can add comma-separated
project-relative masks with `OPENCLAUDIA_PROJECT_SECRET_MASKS`. Hardlinked
read targets are rejected on Unix, and writable project trees are rejected if
a multiply-linked inode has aliases outside the tree.

Session temporary directories are private (`0700` on Unix), individually
granted, and removed at session release only after an identity check. The
process-wide OS temporary directory is never a file-tool capability.

## Linux subprocess boundary

Linux uses a root-owned, non-writable Bubblewrap binary found only in trusted
system locations. Startup probes namespace creation before an agent-capable
surface starts. Each process starts from an empty mount namespace with:

- selected system and toolchain runtime trees mounted read-only;
- explicit session roots mounted with their declared access;
- private `/tmp`, `/run`, `/proc`, `/dev`, `HOME`, and package-manager state;
- no host `/sys`, `/etc`, home directory, runtime directory, or IPC sockets;
- all capabilities dropped, a new PID/user/network namespace, nested user
  namespaces disabled, and parent-death/process-group cleanup;
- a versioned seccomp filter denying socket creation, mount and namespace
  changes, `ptrace`, BPF, performance events, keyrings, kernel module/kexec,
  cross-process memory access, file-handle APIs, `userfaultfd`, and
  `io_uring`;
- inherited descriptors closed except stdio and the pinned seccomp filter;
- CPU, address-space, process/thread, file-descriptor, per-file-size,
  output-capture, and wall-time limits.

Writable roots are scanned before launch. Nested mounts, external hardlink
aliases, Unix sockets, FIFOs, and device nodes make startup fail closed.
Bubblewrap uses non-recursive binds in a private mount namespace so a later
host mount does not become a sandbox mount.

All subprocess callers select one of: `Shell`, `RepositoryHook`,
`LanguageServer`, `StaticAnalyzer`, `QualityGate`, `DocumentParser`,
`McpStdio`, or `GitWorktree`. Callers cannot supply Bubblewrap flags.

## Environment and toolchains

The launcher clears ambient environment authority. Locale is preserved;
credential, proxy, SSH agent, desktop bus, display, dynamic-loader,
language-runtime injection, and package-registry variables are absent unless
the host names an exact grant in `OPENCLAUDIA_AGENT_ENV_GRANTS`. Reserved
policy variables and credential-shaped names cannot be granted.

Linux exposes `/usr`, Nix store/profiles, Rustup, Cargo binaries, and Cargo's
registry cache read-only when present. It does not expose the rest of the
user's home, Cargo credentials, shell startup files, histories, package
manager auth, or writable host caches. Dependency installation can use
vendored/project-local inputs; agent subprocess network access is denied.
Custom tools require an explicit filesystem capability and remain subject to
the executable and profile checks.

## Git linked worktrees

Ordinary Bash sees a minimal read-only `.git` view: `HEAD`, index, objects,
refs, packed refs, and shallow metadata. Config, hooks, reflogs, credentials,
pagers, helpers, filters, and external diff commands are absent or disabled.

For linked worktrees, the `.git` indirection, `commondir`, admin-parent
relationship, and backlink are validated on the host. Only the selected
worktree admin files and common object/ref state are mounted. A forged
indirection cannot mount an arbitrary path. Mutating worktree operations use
the dedicated `GitWorktree` profile with hardened Git config and an audited
metadata-write grant.

## MCP and hooks

Repository MCP servers require an exact
`OPENCLAUDIA_TRUST_MCP_SERVERS=plugin/server` grant. Executables are
canonicalized, must be outside agent-writable roots, and have trusted ancestry.
Sensitive environment values require exact names in
`OPENCLAUDIA_MCP_ENV_GRANTS`. Stdio MCP runs in `McpStdio` with network denied;
revocation terminates and unregisters it.

Command hooks default to `FullSandbox`. `none` and `env_scrub` require the host
to start with `OPENCLAUDIA_TRUST_UNSANDBOXED_HOOKS=true`; this emits a warning
and deliberately transfers host authority to the configured hook. Models
cannot request that grant.

## Platform status and deliberate non-support

- **Linux:** enforced and covered by the adversarial escape suite.
- **macOS:** descriptor-relative file tools are available, but agent
  subprocesses fail closed. The deprecated `sandbox-exec` interface is not
  treated as a production boundary. A maintained implementation requires a
  separately signed/entitled helper or another Apple-supported isolation
  design.
- **Windows:** agent subprocess and file tools fail closed. A production
  implementation requires AppContainer/restricted tokens, Job objects,
  mitigation policy, ACL capability projection, and reparse-safe traversal.

There is no automatic unsandboxed fallback. For incident recovery only, a host
operator may set `OPENCLAUDIA_BASH_SANDBOX=off` before startup. This disables
the subprocess boundary, exposes host network/filesystem authority, is
reported by diagnostics, and must never be used for untrusted repositories.

## Explicitly unsupported capabilities

- Loopback-only or destination-specific subprocess networking is not shipped.
  `OPENCLAUDIA_AGENT_NETWORK` accepts only `denied`; other values fail session
  creation. A future design needs an isolated network namespace plus an
  authenticated destination broker, not restoration of the host namespace.
- Total writable-byte quotas and cgroup-v2 scopes are not available to an
  ordinary process unless the service manager delegates a writable cgroup or
  project filesystem. The current fallback enforces per-file `RLIMIT_FSIZE`,
  address-space/CPU/process/fd caps, bounded output, wall deadlines, and full
  process-tree termination. Operators needing a hard aggregate disk/memory
  quota must run OpenClaudia inside a delegated service/container quota.
- Agent-facing rename and delete file tools do not exist. Their race tests are
  therefore non-applicable; future implementations must use descriptor-
  relative primitives before being registered.
- Attachments have no implicit path authority. A host must materialize them
  under the session private temp directory or explicitly register their root.

## Diagnostics, audit, and incident response

`openclaudia doctor` reports the backend, health, network state, syscall
filter, resource limits, root counts, environment-grant count, and opt-out
state without printing values. It also reports each configured MCP server's
trust requirement, transport/profile, and grant counts. Interactive tool
permission prompts describe the enforced data/network scope in addition to
the command or destination. Structured tracing records sandbox preflight,
starts, denials, explicit trust decisions, metadata-write grants,
cancellations, and terminations.

If an escape is suspected: stop the session, preserve logs, revoke MCP/hook
trust grants and provider credentials, inspect project hardlinks/mounts and
generated executables, run `openclaudia doctor`, and reproduce only with
test-owned local sentinels. Do not probe unrelated host data.
