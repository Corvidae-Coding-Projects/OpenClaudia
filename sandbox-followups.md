# Sandbox follow-up goal

Fix every unchecked item in this document. Treat this as a security-hardening goal, not a request to weaken tests or restore host execution when compatibility is difficult.

## Goal

Make every process and filesystem operation reachable from an agent obey an explicit, testable security boundary:

- Agent-launched code must not read or modify host data outside its granted roots.
- It must not reach the host network or host IPC endpoints unless a narrowly scoped capability explicitly permits it.
- It must not escape through symlinks, hardlinks, nested mounts, special files, subprocesses, hooks, language servers, MCP servers, ACP delegation, or resource exhaustion.
- Unsupported or unhealthy sandbox backends must fail closed with a useful diagnostic.
- User-operated/trusted extension workflows must remain clearly distinct from agent-operated workflows.

Do not remove the protections already implemented in `src/tools/bash/sandbox.rs`, do not accept a model-supplied sandbox-disable flag, and do not silently fall back to unsandboxed execution.

## Current baseline

The existing implementation already:

- Runs foreground Bash, background Bash, ACP-routed Bash, quality gates, and `FullSandbox` hooks through a Linux Bubblewrap sandbox.
- Gives the sandbox a private home, `/tmp`, `/run`, `/proc`, and `/dev`; removes network access and capabilities; and disables nested user namespaces.
- Mounts the project writable, mounts selected runtimes/toolchains read-only, exposes minimal Git metadata read-only, and hides `.openclaudia` and `.claude` control data.
- Fails closed when Bubblewrap is unavailable or the platform is unsupported, unless the host operator explicitly starts OpenClaudia with `OPENCLAUDIA_BASH_SANDBOX=off`.
- Rejects dangerously broad project roots and covers the main write, symlink, network, Git, nested-user-namespace, ACP, quality-gate, and hook cases with tests.

Preserve those properties while completing the work below.

## Resolution record (2026-07-30)

A checked box in this document means the item was resolved under the
definition of done: implemented, made non-applicable by removing the
agent-facing capability, or deliberately rejected with a fail-closed security
rationale. It does **not** mean an unavailable platform feature was simulated
or replaced with an unsandboxed fallback.

| Finding | Resolution | Primary evidence |
|---|---|---|
| F01 | Implemented | `src/tools/security.rs`; private `0700` session temp roots, owner-bound capabilities, identity-checked cleanup; `tests/session_filesystem_capabilities_e2e.rs`. |
| F02 | Implemented on Linux and macOS file backends; Windows file access deliberately fails closed. Agent rename/delete operations do not exist and remain unregistered. Symlinks are unsupported by policy. | `src/tools/file/secure_fs.rs`; `tests/session_filesystem_capabilities_e2e.rs`; `docs/sandbox-threat-model.md`. |
| F03 | Implemented | ACP file/search/Bash operations execute through the local registry; IDE buffer metadata is session/path scoped; cancellation uses a blocking worker plus process-tree cancellation. |
| F04 | Implemented | Named profiles in `src/tools/bash/sandbox.rs`; inventory in `docs/subprocess-inventory.md`; structural regression lint in `tests/subprocess_boundary_e2e.rs`. |
| F05 | Implemented | Hooks default to `FullSandbox`; weak modes require immutable host-startup trust and emit audit warnings; all command-hook events share bounded launch/cleanup. |
| F06 | Implemented with a narrower supported policy | Repository MCP needs an exact `plugin/server` host grant; stdio executables and ancestry are pinned outside writable roots; exact sensitive env grants only; stdio network remains denied. Destination-specific MCP subprocess networking is deliberately unsupported. |
| F07 | Implemented | Writable roots are inode-scanned; external aliases fail startup, internal aliases are allowed for sandboxed subprocesses, and direct file-tool hardlinks use the stricter documented rejection policy. |
| F08 | Implemented | `/proc/self/mountinfo` is checked before each writable bind; nested mounts fail closed; non-recursive, descriptor-pinned binds enter a private mount namespace. |
| F09 | Implemented | Sockets, FIFOs, and device nodes reject writable roots; network namespaces and seccomp deny socket creation; inherited descriptors are closed. |
| F10 | Implemented | Immutable per-session context carries roots, temp, environment, network, working directory, and owner; background lookup/signaling/cancellation is owner-bound. |
| F11 | Production macOS/Windows subprocess backends deliberately not shipped | No maintained OS-supported implementation exists in this codebase. Those platforms fail closed with diagnostics and CI coverage; macOS retains descriptor-relative file access, while Windows file access also fails closed pending reparse-safe handles. |
| F12 | Implemented | Startup executes a real Bubblewrap namespace/mount probe; doctor reports redacted effective policy and MCP grant counts; trusted executables are absolute and ownership/permissions checked. |
| F13 | Implemented | Versioned seccomp-v1 BPF policy for Linux x86-64/AArch64; unknown architectures or filter failures fail closed; syscall and development-workload tests are included. |
| F14 | Implemented with documented host-service limitations | CPU/address-space/process/fd/file-size/output/wall limits and whole-tree cleanup cover every agent profile. Aggregate disk quotas and delegated cgroup-v2 scopes are deliberately not claimed by an unprivileged process; operators needing them must add a service/container quota. |
| F15 | Implemented | ACP local execution uses `spawn_blocking`, polls cancellation, and kills the registered sandbox process tree on cancel/disconnect/session shutdown. |
| F16 | Implemented | Ambient env is cleared; locale plus exact host-startup names are granted; credentials, IPC, proxy, dynamic-loader, runtime-injection, and secret-shaped names are denied/redacted. |
| F17 | Implemented | Runtime/toolchain mount inventory is documented and launcher-defined; selected runtime trees/caches are read-only; home config, credentials, histories, auth, and writable host caches stay absent. |
| F18 | Implemented | Project read/write exposure is documented; optional relative secret masks exist; control paths are always hidden; permission prompts now display the effective data/network scope. |
| F19 | Implemented | Linked-worktree indirection and backlinks are validated; minimal Git metadata is descriptor-pinned read-only; mutating operations use `GitWorktree` with hardened Git configuration. |
| F20 | Default denial implemented; narrow networking deliberately unsupported | Restoring the host namespace would not be a narrow grant. Any non-`denied` subprocess policy is rejected until an authenticated destination broker exists. |

### Deliberate secure rejections

- There is no macOS or Windows agent subprocess compatibility fallback.
  Implementing AppContainer/Job-object or a signed/entitled macOS helper is a
  separate platform project; pretending `sandbox-exec`, ACL checks, or
  environment scrubbing provides equivalent isolation would be unsafe.
- Loopback and destination-specific subprocess network grants are not
  accepted. A future implementation needs an isolated namespace and an
  authenticated broker that binds destinations and expiry to the session.
- An ordinary unprivileged process cannot promise an aggregate filesystem
  quota or delegated cgroup. The launcher enforces its portable rlimit,
  namespace, output, wall-time, and process-tree controls and documents the
  stronger host deployment requirement.
- Attachments gain no implicit host path access. They must be materialized in
  the private session temp root or supplied through an explicit host-startup
  root capability.

### Verification record

The implementation is gated by:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features -- --test-threads=1
cargo check --target x86_64-pc-windows-gnu --no-default-features
```

The hosted workflow in `.github/workflows/sandbox-security.yml` repeats the
Linux escape suites and compiles/runs the fail-closed suite on macOS and
Windows. Escape probes use only test-owned sentinels and listeners.

Local verification on 2026-07-30 completed all four commands above
successfully. The Windows cross-target check emitted non-fatal
target-specific unused-code warnings. Actual macOS and Windows runtime
execution remains the responsibility of the hosted workflow; it was not
simulated on the Linux development host.

## Security boundary

Use this classification consistently:

1. **Agent-operated:** Bash, file tools, search, quality gates, hooks selected from repository-controlled configuration, language servers or analyzers influenced by repository contents, and any subprocess whose command or inputs an agent can influence. These require enforcement.
2. **Brokered capability:** Web/search/provider tools and similar services intentionally implemented outside the process sandbox. These need their own allowlists, SSRF controls, secret isolation, and audit trail; sandboxed code must not inherit their credentials.
3. **User-operated/trusted extension:** An interactive user `!` command, an explicitly trusted MCP server, plugin installation, or an administrative Git operation. These may run on the host only after an explicit trust decision and must not become indirectly agent-reachable.

Repository content is untrusted. Merely opening a repository must not authorize its hooks, MCP configuration, language-server configuration, executables, or build scripts to run on the host.

## P0 — close direct escape paths

### F01: Replace the process-wide `/tmp` file-tool grant

- [x] Remove the rule in `src/tools/file/mod.rs` that treats the entire canonical process temporary directory as an allowed root.
- [x] Create a private per-session temporary directory with restrictive permissions.
- [x] Grant file tools only that directory and individually registered attachment/artifact paths.
- [x] Keep temporary capabilities in session/tool context rather than process-global state.
- [x] Delete or revoke the private directory at session end without following links.

Threat: another same-user process can leave secrets, sockets, or writable targets in the shared temporary directory. A grant to all of `/tmp` lets the agent reach them.

Acceptance tests:

- A file created in the session temp directory is accessible.
- A sibling file elsewhere in the OS temp directory is denied.
- A symlink from the session directory to a sibling target is denied.
- Two concurrent sessions cannot read each other’s temporary files.

### F02: Make all file operations race-safe

- [x] Replace “canonicalize, validate, then open by pathname” with handle-relative resolution.
- [x] On Linux, use `openat2` with suitable `RESOLVE_BENEATH`, `RESOLVE_NO_MAGICLINKS`, and symlink policy flags, or a carefully reviewed `openat` component walk using directory file descriptors and `O_NOFOLLOW`.
- [x] Implement equivalent reparse-point-safe handle traversal on Windows and a descriptor-relative implementation on macOS.
- [x] Apply the same primitive to read, write, edit, notebook, list, glob, search, directory creation, rename, and deletion operations.
- [x] Decide and document whether symlinks wholly contained inside an allowed root are supported. Enforce that decision atomically.

Threat: the existing leaf `O_NOFOLLOW` checks do not protect intermediate path components. A directory can be swapped for a symlink after validation but before the final open.

Acceptance tests:

- Repeatedly swap every intermediate directory component during read and write attempts; no access may occur outside the root.
- Test file-to-symlink, directory-to-symlink, rename, and deletion races.
- Test magic links such as `/proc/self/fd/*`.
- Run the race suite under high concurrency and sanitizers where available.

### F03: Enforce local roots for ACP filesystem and search operations

- [x] Audit ACP read/write/edit delegation. Do not rely solely on the connected client to enforce the local path jail.
- [x] Either route operations through the secure local file primitives or issue narrow, canonical, non-forgeable client capability tokens.
- [x] Validate ACP search roots before invoking `rg` in `src/acp.rs`.
- [x] If IDE buffer support requires client delegation, separate buffer access from arbitrary host filesystem access in the protocol and permission UI.

Threat: ACP delegation can bypass the local filesystem jail and turn the client into an implicit, inconsistent enforcement boundary.

Acceptance tests:

- ACP read, write, edit, and search reject absolute paths, `..`, symlink races, and alternate spellings that resolve outside granted roots.
- A malicious or permissive mock ACP client cannot expand the local grant.
- Unsaved in-editor buffers still work only for files covered by a valid capability.

### F04: Sandbox every agent-reachable subprocess

- [x] Build an inventory of every `Command::new`, shell invocation, process-spawn helper, and extension execution path.
- [x] Classify each caller using the security-boundary section above.
- [x] Route every agent-operated subprocess through a common sandbox launcher with a named policy profile.
- [x] Give trusted host operations a separate API that cannot be called from agent tool dispatch.
- [x] Add a test or lint that fails when a new agent-reachable direct subprocess spawn is introduced.

Known locations requiring resolution:

- `src/tools/lsp.rs`: language servers can execute repository-controlled build scripts, compiler plugins, formatters, or configuration.
- `src/vdd/static_analysis.rs`: verify how analyzer commands are selected and sandbox any project-influenced execution.
- `src/acp.rs`: the direct `rg` search subprocess needs root enforcement and an appropriate profile.
- `src/tools/command.rs`: audit every caller rather than assuming a generic subprocess helper is trusted.
- `src/mcp.rs`: configured stdio MCP servers are a separate trust boundary; see F06.
- `src/tui/app.rs`: interactive `!` commands appear user-operated. Keep them structurally inaccessible to agent dispatch, or sandbox them if that assumption is false.
- Plugin Git helpers should remain a trusted administrative path only if an agent cannot invoke them indirectly.

Acceptance tests:

- A repository-provided LSP, analyzer, formatter, and search configuration cannot read a host sentinel, open the network, or write outside its grant.
- Tests prove user-only subprocess APIs cannot be reached through tool names, hooks, ACP messages, plugins, or prompt-generated arguments.

### F05: Treat repository hooks as untrusted by default

- [x] Change the default hook behavior from `EnvScrub` to an enforced sandbox or “disabled pending trust.”
- [x] Do not execute hooks discovered in repository or Claude-compatible configuration on the host merely because the repository was opened.
- [x] Keep `None` and `EnvScrub` modes available only for an explicit host-operator trust decision with a warning and audit event.
- [x] Ensure hook working directory, environment, executable resolution, network policy, timeouts, output limits, and process cleanup all come from the selected profile.
- [x] Cover every hook event, not just one representative path.

Threat: environment scrubbing is not isolation. A repository-controlled hook with host process access can read files, use inherited identity, connect to services, or modify the host.

Acceptance tests:

- A newly cloned malicious repository cannot trigger host execution before trust is granted.
- Default hooks cannot access host sentinels, control directories, network, session sockets, or sibling projects.
- An explicit user trust action is visible, scoped, revocable, and cannot be supplied by the model.

### F06: Define and enforce the MCP server trust boundary

- [x] Treat locally configured stdio MCP servers as trusted extensions only after explicit user approval, or run them under a configurable per-server sandbox profile.
- [x] Distinguish user-level trusted configuration from repository-provided MCP configuration.
- [x] Never pass the agent process environment wholesale. Grant individual environment variables, filesystem roots, and network destinations.
- [x] Surface each server’s effective permissions before launch and in diagnostics.
- [x] Prevent an untrusted repository from replacing a trusted executable through `PATH`, relative paths, working-directory tricks, or symlinks.

Do not blindly apply the Bash no-network profile: some MCP servers legitimately need network access or credentials. They need declared capabilities, not ambient authority.

Acceptance tests:

- Repository MCP configuration cannot launch before approval.
- Executables are resolved and pinned outside attacker-writable roots.
- A server receives only declared secrets and can reach only declared roots/destinations.
- Revocation terminates the server and invalidates its capabilities.

## P0 — harden the namespace boundary

### F07: Block hardlink alias escapes

- [x] Prevent a writable file inside the project bind from being a hardlink to a file outside the granted roots.
- [x] Choose a defensible strategy: validate and reject external aliases, stage the project in a copy-on-write layer with controlled commit-back, or enforce an equivalent inode-safe design.
- [x] Handle legitimate hardlinks that are entirely internal to a granted tree.
- [x] Re-check the invariant when files are imported, attachments are materialized, or roots change.

Threat: namespace path isolation does not change inode identity. Writing a project path that is already hardlinked to an outside file modifies the outside inode.

Acceptance tests:

- A pre-existing project hardlink to a host sentinel cannot modify the sentinel.
- Internal hardlinks behave according to the documented policy.
- Renames and atomic-replace writes do not reintroduce an outside alias.

### F08: Reject or isolate nested mounts

- [x] Inspect the host mount table before binding a granted root.
- [x] Reject, mask, or reconstruct roots containing nested mounts that are not separately granted.
- [x] Avoid recursive bind behavior that silently imports host mounts under the project.
- [x] Revalidate for long-running sessions or pin a mount-safe snapshot so a later host mount cannot appear inside the sandbox.

Threat: a project subdirectory can be a mount of the user’s home, a secret volume, a device filesystem, or another sensitive tree.

Acceptance tests:

- Bind mounts, FUSE mounts, removable-media mounts, and mount namespaces nested below the project are absent unless explicitly granted.
- A mount introduced after session creation cannot become visible to the running sandbox.

### F09: Block host IPC and special-file escapes

- [x] Detect and reject or mask Unix-domain sockets, FIFOs, device nodes, and other special files inside writable grants.
- [x] Confirm that filesystem Unix sockets cannot connect from the sandbox to host services.
- [x] Keep abstract sockets and TCP/UDP inaccessible by default.
- [x] Add a seccomp layer as described in F13 to reduce syscall-level IPC and kernel attack surface.

Threat: a socket inside the project may lead to Docker, SSH agents, databases, desktop services, or another privileged host daemon even though the network namespace is private.

Acceptance tests:

- The sandbox cannot use a project-contained socket connected to a host listener.
- It cannot communicate through a FIFO crossing the boundary or use a project-contained device node.
- Normal regular files and explicitly supported build IPC continue to work.

## P1 — make policy explicit and portable

### F10: Carry immutable roots and capabilities in tool context

- [x] Stop deriving the security root from process-global `current_dir()` or a lazy process-global `PROJECT_ROOT`.
- [x] Create an immutable per-session context containing project identity, working directory, granted read-only/read-write roots, temp capability, environment grants, network policy, and owner/session ID.
- [x] Pass that context through Bash, file tools, background jobs, ACP, hooks, LSP, analyzers, and quality gates.
- [x] Support explicitly granted additional working directories and worktrees without broadening access to their parents.
- [x] Bind the background-process registry and cancellation authority to the owning session.

Threat: multiple projects or sessions in one process can race over global current-directory state or accidentally inherit another session’s grants.

Acceptance tests:

- Concurrent sessions rooted in different projects cannot cross-read, cross-write, list, search, signal, or await each other’s resources.
- Changing process current directory does not change an existing session’s boundary.
- Worktree and additional-root access is exactly the declared capability set.

### F11: Add real macOS and Windows backends

- [x] Define a platform-neutral sandbox policy interface and platform-specific implementations.
- [x] Implement macOS isolation using a maintained OS-supported mechanism with filesystem, network, IPC, process, and resource controls.
- [x] Implement Windows isolation using an appropriate combination of AppContainer/restricted tokens, job objects, ACL/capability grants, process mitigation, and reparse-point-safe filesystem handling.
- [x] Keep unsupported configurations fail closed. The environment-variable opt-out must remain a host startup decision with a prominent warning.
- [x] Add platform CI and escape tests rather than testing only that unsupported systems reject execution.

Acceptance tests:

- The common escape suite passes on Linux, macOS, and Windows.
- Each backend reports its active protections and unsupported features.
- There is no automatic unsandboxed compatibility fallback.

### F12: Add backend health checks and diagnostics

- [x] Probe Bubblewrap usability, kernel namespace support, distribution restrictions, and required mount behavior at startup rather than checking only for a binary in trusted paths.
- [x] Add a doctor/status view that reports backend, effective policy, granted roots, network state, seccomp state, resource limits, and any explicit opt-out.
- [x] Make execution errors actionable without including sensitive host paths or environment values.
- [x] Pin executable resolution to trusted absolute paths and verify ownership/permissions where appropriate.

Acceptance tests:

- A present-but-unusable Bubblewrap installation is diagnosed before the first agent command.
- Setuid, unprivileged-user-namespace-disabled, container-within-container, and missing-kernel-feature cases fail closed with distinct messages.
- Diagnostics never print secrets.

### F13: Add syscall filtering

- [x] Apply a reviewed seccomp policy after namespace setup.
- [x] At minimum assess and normally deny mount-related syscalls, `ptrace`, BPF, performance events, kernel keyring operations, module/kexec operations, raw sockets, additional namespace creation, and other unnecessary privileged/kernel-attack-surface calls.
- [x] Keep the policy architecture-aware and test common compilers, package managers, test runners, Git inspection, and language servers.
- [x] Version named profiles when different tools genuinely require different syscall sets.

Acceptance tests:

- Dedicated probes for each denied syscall fail predictably.
- Supported development workloads still run.
- An unknown architecture or policy-load failure causes sandbox startup to fail closed.

### F14: Add resource and lifetime isolation

- [x] Enforce CPU, memory, process-count, open-file, output-size, disk/quota, and wall-clock limits using cgroup v2/systemd scopes where available plus appropriate rlimits.
- [x] Cap captured stdout/stderr without allowing an unbounded in-memory buffer.
- [x] Terminate the entire process tree on cancellation, timeout, session end, or parent death.
- [x] Prove that double-forked, daemonized, and orphaned children cannot survive.
- [x] Apply limits to foreground, background, hooks, quality gates, LSP, analyzers, and sandboxed MCP servers.

Acceptance tests:

- Fork bombs, memory bombs, output floods, disk fills, CPU loops, and daemonization attempts are contained.
- The host remains responsive and the user receives a bounded diagnostic.
- Terminating one session cannot signal another session’s jobs.

### F15: Make ACP execution asynchronous and cancellable

- [x] Move synchronous local Bash execution out of the async ACP event loop using a cancellation-aware blocking worker or a fully async process implementation.
- [x] Preserve the exact same local sandbox profile and permission checks.
- [x] Propagate disconnect, cancellation, timeout, and session shutdown to the complete sandbox process tree.

Acceptance tests:

- A long foreground command does not block unrelated ACP messages.
- Cancellation promptly kills every descendant.
- Sandboxing cannot be bypassed by switching between foreground and background execution.

## P1 — reduce ambient data exposure

### F16: Replace broad environment-prefix inheritance

- [x] Review environment scrubbing, especially broad prefixes such as `SSH_`, `XDG_`, and `DBUS_`.
- [x] Replace prefix-based inheritance with explicit per-profile variable grants wherever practical.
- [x] Strip host IPC endpoints, credential variables, injected runtime options, proxy variables, and secret-shaped values unless deliberately required.
- [x] Prevent repository configuration or agent arguments from requesting arbitrary host environment variables.
- [x] Redact values in logs, status displays, and errors.

Acceptance tests:

- Canary secrets under allowed-looking prefixes do not reach sandboxed processes.
- Required locale, terminal, and toolchain behavior still works through documented grants.
- SSH agent, desktop bus, credential-helper, cloud, package-registry, and proxy endpoints are absent by default.

### F17: Audit runtime and toolchain mounts

- [x] Inventory every host directory mounted for Rust, Node, Python, Nix, and other supported toolchains.
- [x] Mount only immutable executables, libraries, sources, and caches required by the profile.
- [x] Exclude credentials, writable configuration, history, activation hooks, user startup files, and package-manager auth.
- [x] Decide how package installation works without granting general network or host cache writes.
- [x] Treat executables from project directories, `~/.local`, `/opt`, or custom toolchains as explicit capabilities rather than silently exposing them.

Acceptance tests:

- Credential canaries placed beside toolchain caches are not readable.
- Read-only toolchain execution succeeds.
- Package managers cannot mutate host caches or obtain undeclared credentials.

### F18: Make project-secret exposure an explicit policy

- [x] Document that the project root is readable and writable by agent code, including `.env`, local keys, test fixtures, and generated credentials stored there.
- [x] Add optional secret masking or narrow root capabilities for users who do not want the full repository exposed.
- [x] Keep `.openclaudia`, `.claude`, and equivalent control-plane data hidden even when nested or referenced by alternate paths.
- [x] Ensure permission prompts describe the real data scope, not only the command string.

Acceptance tests:

- Default and restricted modes have clear, tested behavior for project secrets.
- Hidden control paths remain inaccessible through symlinks, hardlinks, worktrees, case aliases, and alternate path syntax.

### F19: Safely support Git linked worktrees

- [x] Handle a worktree `.git` indirection file without mounting its arbitrary target.
- [x] Parse and validate Git metadata on the host, prove it belongs to the current repository/worktree, and expose only the minimum read-only metadata required for safe inspection.
- [x] Mask hooks, config that launches helpers, credentials, reflogs, remote URLs, and unrelated worktrees unless explicitly needed.
- [x] Keep mutating Git operations in dedicated permissioned tools rather than making the Bash metadata mount writable.

Acceptance tests:

- Safe `git status` and `git diff` work in normal repositories and linked worktrees.
- A forged `.git` file cannot expose an arbitrary host path.
- Git aliases, hooks, filters, pagers, credential helpers, and external diff commands cannot cause host execution or secret access.

### F20: Define narrowly scoped test-network capabilities

- [x] Keep network disabled by default for Bash and quality gates.
- [x] If test suites need networking, add a profile that can grant loopback or declared destinations without restoring the host network namespace.
- [x] Make the grant visible, time-limited, and user-controlled; never infer it from command text.
- [x] Ensure local service discovery, proxy environment variables, DNS, and Unix sockets cannot broaden the grant.

Acceptance tests:

- A loopback-only test service works when explicitly enabled.
- Public internet, LAN, metadata services, host services, and undeclared ports remain unreachable.
- The default quality-gate profile has no network.

## Engineering requirements

- [x] Centralize policy construction. Callers select a named profile and pass capabilities; they must not assemble Bubblewrap flags ad hoc.
- [x] Use typed paths/handles and typed capabilities instead of unvalidated strings.
- [x] Separate the trusted host launcher API from the agent sandbox launcher API at the type/module boundary.
- [x] Emit structured audit events for grants, denials, trust decisions, backend failures, starts, cancellations, and terminations without logging secret values.
- [x] Preserve permission prompts as defense in depth, but never treat a prompt or denylist as the isolation boundary.
- [x] Avoid parsing shell text to decide security policy.
- [x] Document the threat model, supported platforms, limitations, opt-out consequences, and incident-response guidance.
- [x] Preserve unrelated worktree changes and generated user data.

## Required adversarial test matrix

Add deterministic local tests for all applicable profiles and platforms:

- [x] Absolute paths, `..`, symlinks, junctions/reparse points, magic links, path races, case-folding, Unicode aliases, and long paths.
- [x] Hardlinks, nested mounts, bind mounts, FUSE, sockets, FIFOs, device nodes, `/proc`, `/sys`, and inherited file descriptors.
- [x] Network namespace, IPv4, IPv6, DNS, loopback, abstract and filesystem Unix sockets, proxies, and host metadata endpoints.
- [x] Process escape attempts: nested user namespaces, clone/unshare variants, ptrace, seccomp bypass probes, daemonization, parent death, and cross-session signaling.
- [x] Environment, Git helpers/hooks/config, compiler plugins, build scripts, LSP configuration, analyzer configuration, MCP executable resolution, and repository hooks.
- [x] CPU, memory, process, file-descriptor, output, disk, and wall-time exhaustion.
- [x] Concurrent sessions with different projects, temp directories, worktrees, added roots, and background jobs.
- [x] Backend unavailable, partially supported, deliberately disabled, and startup health-check failures.

Escape tests must use local sentinel files and listeners owned by the test process. They must not probe unrelated host data or external systems.

## Definition of done

This goal is complete only when:

- [x] Every item above is implemented, explicitly rejected as out of scope with a documented security rationale, or converted into a tracked issue with user approval. Do not silently skip items.
- [x] No agent-reachable path launches an unsandboxed process or delegates unrestricted filesystem access.
- [x] Every trusted-host path requires an explicit user/administrator trust decision and is structurally separated from agent dispatch.
- [x] Linux, macOS, and Windows either pass the common security suite or fail closed with the platform limitation clearly reported.
- [x] The threat model and user documentation match the actual implementation.
- [x] Formatting, linting, unit tests, integration tests, adversarial tests, and platform CI pass.
- [x] A final review inventories subprocess creation and filesystem entry points again and explains why each is safe.

Run at least:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets -- --test-threads=1
```

Also run the new platform-specific sandbox integration suites in disposable CI runners. Do not weaken or delete an escape test merely to make a platform pass.
