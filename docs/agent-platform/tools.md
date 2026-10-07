# Tools

Tool declaration, routing, the built-in tool contracts, command execution,
`apply_patch`, approvals, sandboxing, exec policy and MCP. The structure follows
Codex `core/src/tools/`, `unified_exec/`, `apply-patch/`, `execpolicy/` and
`linux-sandbox/`.

Split of responsibilities:

- **Control plane** (`chatbot-agent`): tool specs, routing, argument validation,
  approval decisions, exec-policy evaluation, output formatting and truncation.
- **Runner** (`agent-runner`): executes the effect (process, file write, MCP
  stdio server) inside the inner sandbox and reports results. The runner
  re-checks sandbox policy; it never trusts the control plane to have filtered
  paths.

## 1. Concepts

```rust
enum ToolSpec {
    Function { name: String, description: String, parameters: JsonSchema, strict: bool, output_schema: Option<JsonSchema> },
    Namespace { name: String, description: String, tools: Vec<ToolSpec> },
    Freeform { name: String, description: String, format: FreeformFormat },   // wire type "custom"
    WebSearch(HostedWebSearch),                                                // provider-hosted
}

enum FreeformFormat { Text, Grammar { syntax: GrammarSyntax /* Lark */, definition: String } }

enum ToolPayload {
    Function { arguments: String },   // raw JSON string from the model
    Custom { input: String },
    Mcp { server: String, tool: String, arguments: serde_json::Value },
}

struct ToolCall { tool_name: ToolName, call_id: CallId, payload: ToolPayload }

struct ToolInvocation<'a> {
    call: ToolCall,
    turn: &'a TurnContext,
    step: &'a StepContext,
    events: &'a EventSink,
    runner: &'a dyn ToolExecutorPort,     // architecture.md §6
    approvals: &'a ApprovalBroker,
    cancel: CancellationToken,
}

#[async_trait]
trait ToolHandler: Send + Sync {
    fn spec(&self, caps: &ModelCapabilities, turn: &TurnContext) -> Option<ToolSpec>;  // None = not exposed
    fn parallel_safe(&self, call: &ToolCall) -> bool;
    fn kind(&self) -> ToolKind;          // Builtin | Mcp | Dynamic | Harness
    async fn handle(&self, inv: ToolInvocation<'_>) -> Result<ToolOutput, ToolError>;
}

struct ToolOutput {
    model: ToolOutputPayload,            // what the model sees (agent-loop.md §4.1)
    item: ThreadItemPatch,               // what the UI item is completed with
    success: bool,
    history_token_cap: Option<u64>,      // overrides default truncation for this output
}
```

`ToolError` has two classes: `RespondToModel(String)` (bad arguments, file not
found, denied by user — the model sees the message and continues) and
`Fatal(TurnError)` (runner lost, key custody lost — the turn fails).

## 2. Registry and router

### 2.1 Registry

`ToolRegistry` maps canonical `ToolName { namespace: Option<String>, name }` to
handlers. Names are unique per step. Registration sources, in order:

1. Built-ins (§3), filtered by feature gates and model capabilities.
2. Collaboration tools (agent-loop.md §9).
3. MCP tools (§9), qualified as `mcp__<server>__<tool>` and truncated to 64
   characters with a stable hash suffix when longer.
4. Dynamic client tools registered by the UI or a connected client (§10).

A later source cannot shadow an earlier one; a collision drops the later tool
and records a `ToolRegistrationWarning` event.

### 2.2 Per-step build

`build_tool_router(turn, step)` produces the tool list for one sampling
request. Inputs: `FeatureSet`, model capabilities (freeform tools, parallel
calls, image input, hosted search), workspace presence, sandbox profile,
collaboration mode, agent depth, MCP catalog snapshot, privacy level.

Gates:

| Tool | Present when |
|---|---|
| `exec_command`, `write_stdin` | workspace attached and `features.shell` |
| `apply_patch` | workspace attached; freeform if the model supports custom tools, else function form |
| `read_file`, `list_dir`, `grep_files` | workspace attached and `features.fs_tools` (useful for models weak at shell) |
| `view_image` | workspace attached and model accepts images |
| `update_plan` | always in agent threads |
| `request_user_input` | root thread only, and approval policy is not `Never` |
| `web_search` (Brave) | Brave configured and privacy allows Brave |
| hosted `web_search` | provider supports it, privacy allows it, Brave tool not present |
| `load_skill` | skills with implicit invocation exist |
| MCP resource tools | at least one MCP server connected |
| collaboration tools | `features.subagents` and depth < `max_depth` |

In `Plan` collaboration mode, mutating tools (`apply_patch`, `exec_command`
with a writable sandbox) are removed and `exec_command` is offered read-only.

### 2.3 Router

`ToolRouter::build_tool_call(item)`:

- `FunctionCall` → look up by `(namespace, name)`; unknown → `RespondToModel("unknown tool …")`.
- `CustomToolCall` → freeform handlers only.
- Function-form `apply_patch` with `{input}` is normalized to `Custom`.
- A function call named `shell`/`container.exec`/`local_shell` from a model
  trained on older Codex tool names is mapped to `exec_command`
  (compatibility aliases, logged).
- An `exec_command` whose command is exactly an `apply_patch` heredoc
  invocation is intercepted and routed to the patch handler, as Codex does, so
  the patch goes through patch approval and diff tracking.

### 2.4 Parallel execution

As in Codex `tools/parallel.rs`: a per-turn `RwLock<()>`. A call whose handler
reports `parallel_safe` takes a read lock; any other call takes the write lock,
so it runs alone. Results are recorded in call order (agent-loop.md §3.2).

Parallel-safe by default: `read_file`, `list_dir`, `grep_files`, `view_image`,
`web_search`, MCP resource reads, `wait_agent`, `list_agents`. Not parallel-safe:
`exec_command`, `write_stdin`, `apply_patch`, `update_plan`, `spawn_agent`, MCP
tools unless the server config sets `supports_parallel_tool_calls = true`
(default false).

`parallel_tool_calls` is sent to the provider only when the model supports it
and at least one parallel-safe tool is present.

### 2.5 Output limits

Every output passes through `truncate_for_model(output, cap)`:

- Default cap 10,000 tokens per call (estimated at 4 bytes/token), overridable
  by the call (`max_output_tokens`) and by `history_token_cap`.
- Truncation keeps the head and tail halves and inserts
  `…[N tokens truncated]…`. UTF-8 boundaries are respected.
- The untruncated output is stored in the event log (subject to a 1 MiB per
  call limit; beyond that the runner stores a workspace file and the event holds
  its path) so the UI can show it.

## 3. Built-in tools

Schemas are JSON Schema with `additionalProperties: false`; `strict` is set
when the provider supports strict schemas.

### 3.1 `exec_command`

```json
{
  "name": "exec_command",
  "parameters": {
    "type": "object",
    "required": ["cmd"],
    "properties": {
      "cmd":               {"type": "string", "description": "Shell command line."},
      "workdir":           {"type": "string", "description": "Working directory, relative to the workspace root or absolute inside it. Default: turn cwd."},
      "tty":               {"type": "boolean", "description": "Allocate a PTY for interactive programs. Default false."},
      "yield_time_ms":     {"type": "integer", "description": "How long to wait for output before returning. Default 10000; clamped to 250..30000."},
      "max_output_tokens": {"type": "integer", "description": "Output cap for this call. Default 10000."},
      "login":             {"type": "boolean", "description": "Run as a login shell. Default true."},
      "sandbox_permissions": {"enum": ["use_default", "require_escalated"], "description": "Ask to run outside the sandbox. Requires approval."},
      "justification":     {"type": "string", "description": "Shown to the user when approval is needed."},
      "prefix_rule":       {"type": "array", "items": {"type": "string"}, "description": "Suggested exec-policy prefix to allow for future runs."}
    }
  }
}
```

Output text (model-facing), matching Codex `ExecCommandToolOutput`:

```
Chunk ID: 3f2a
Wall time: 1.2034 seconds
Process exited with code 0            | Process running with session ID 7
Original token count: 15234           (only when truncated)
Output:
<output>
```

`sandbox_permissions`, `justification` and `prefix_rule` are exposed only when
the approval policy can ask (not `Never`).

### 3.2 `write_stdin`

```json
{"required": ["session_id"],
 "properties": {
   "session_id":        {"type": "integer"},
   "chars":             {"type": "string", "description": "Bytes to write. Empty polls for output."},
   "yield_time_ms":     {"type": "integer"},
   "max_output_tokens": {"type": "integer"}}}
```

Same output format. Empty `chars` waits at least 5 s for new output (Codex
empty-poll floor) so the model cannot busy-loop.

### 3.3 `apply_patch`

Freeform tool with the Lark grammar in §5.1, or the function form
`{"input": string}` for providers without custom tools. Output: a per-file
summary (`A path`, `M path`, `D path`, `R old -> new`) or the first failing hunk
with the nearest matching context.

### 3.4 File tools

| Tool | Arguments | Notes |
|---|---|---|
| `read_file` | `path`, `offset?` (1-based line), `limit?` (default 2000 lines) | Lines are numbered; binary files return a type summary |
| `list_dir` | `path`, `depth?` (default 2, max 5), `limit?` (default 500 entries) | Gitignored entries hidden unless `include_ignored` |
| `grep_files` | `pattern` (regex), `path?`, `glob?`, `limit?` (default 200) | ripgrep in the runner; returns `path:line:text` |
| `view_image` | `path`, `detail?` (`high` \| `original`) | Returns an `InputImage` content item; max 20 MB, downscaled to provider limits |

These are not in Codex's default set (Codex relies on the shell). They exist
because local models in the provider list are much weaker at shell quoting.
They are read-only and parallel-safe, and they respect the sandbox's read
policy.

### 3.5 `update_plan`

```json
{"required": ["plan"],
 "properties": {
   "explanation": {"type": "string"},
   "plan": {"type": "array", "items": {"type": "object", "required": ["step", "status"],
     "properties": {"step": {"type": "string"},
                    "status": {"enum": ["pending", "in_progress", "completed"]}}}}}}
```

At most one step `in_progress`; violations return an error to the model. The
plan is a `Plan` item replaced in place on each call. Output: `"Plan updated"`.

### 3.6 `request_user_input`

```json
{"required": ["questions"],
 "properties": {"questions": {"type": "array", "maxItems": 4, "items": {
   "type": "object", "required": ["id", "question"],
   "properties": {
     "id": {"type": "string"},
     "header": {"type": "string", "maxLength": 12},
     "question": {"type": "string"},
     "options": {"type": "array", "maxItems": 4, "items": {"type": "object",
        "required": ["label"], "properties": {"label": {"type": "string"}, "description": {"type": "string"}}}},
     "multi_select": {"type": "boolean"},
     "allow_free_text": {"type": "boolean"}}}}}}
```

Creates a pending `UserInputRequest`; the turn status becomes
`awaiting_input`. Answered through `Op::AnswerUserInput`. Unanswered requests
time out with the turn's approval timeout (§6.4) and return `"no answer"`.

### 3.7 `web_search`

The existing Brave integration becomes a regular function tool:
`{query: string, count?: 1..10, freshness?: "day"|"week"|"month"|"year"}`.
Output is the existing compact result format, capped at 8,000 bytes. The
current special-case streaming flow in `chatbot-server/src/search.rs` is
retired once plain chat runs on threads (roadmap phase 3).

### 3.8 `load_skill`

`{name: string}` → the skill body (agent-loop.md §6.3). Allowed only for skills
with `allow_implicit_invocation`.

## 4. Command execution

### 4.1 Request path

```text
handle exec_command:
    args = parse + validate (workdir inside workspace after canonicalization by the runner)
    argv = shell_argv(user shell or /bin/bash, login, cmd)       -- ["bash", "-lc", cmd]
    decision = exec_policy.evaluate(argv, turn)                     -- §8
    approval = approval_requirement(decision, turn.approval_policy, turn.sandbox_policy, args.sandbox_permissions)  -- §6.2
    if approval needed: await ApprovalBroker (may amend policy)
    if decision == Forbidden or denied: return RespondToModel(reason)
    req = ExecRequest { argv, cwd, env: shell_env(turn.shell_env_policy), tty, sandbox, network, yield, cap, timeout }
    send ToolCall to runner; stream ToolProgress as CommandExecution output deltas
    on yield before exit -> session stays registered, return "running with session ID"
    on exit -> return exit code and output
```

### 4.2 Runner process model (`unified_exec`)

| Limit | Value | Codex source |
|---|---|---|
| Concurrent sessions per thread | 64 | `unified_exec` `MAX_UNIFIED_EXEC_PROCESSES` |
| Output buffer per session | 1 MiB ring | `UNIFIED_EXEC_OUTPUT_MAX_BYTES` |
| Yield clamp | 250–30,000 ms, default 10,000 | `clamp_yield_time` |
| Empty poll floor | 5,000 ms | |
| Background session idle timeout | 300 s without a poll, then killed | |
| Non-session exec timeout | 10 s default, exit code 124 on timeout | `exec.rs` |
| Output drain after exit | 2 s | `exec.rs` |
| Output delta events | at most 10,000 per call, coalesced at 16 KiB | `exec.rs` |

- Session ids are small integers per thread; the runner maps them to process
  groups. Kill sends SIGTERM to the group, then SIGKILL after 2 s.
- Pipes mode merges stdout and stderr in arrival order and marks the stream in
  the UI event. PTY mode uses a 120×40 terminal; resize comes from the UI only
  when the user attaches the terminal view.
- Sessions survive interrupt (agent-loop.md §3.3) and are evicted
  least-recently-used when the limit is reached, protecting the 8 most recent.
- Sessions do not survive runner restart; the next `write_stdin` returns
  `session not found (runner restarted)`.

### 4.3 User shell commands

`Op::RunUserShellCommand` (the UI's `!cmd`) runs through the same runner path
with the turn's sandbox, no approval (the user typed it), and records a
`CommandExecution { source: User }` item plus a history message so the model
sees what the user ran.

## 5. `apply_patch`

### 5.1 Grammar

Identical to Codex `core/assets/tools/apply_patch.lark`, so models trained on
Codex produce valid patches:

```lark
start: begin_patch hunk+ end_patch
begin_patch: "*** Begin Patch" LF
end_patch: "*** End Patch" LF?
hunk: add_hunk | delete_hunk | update_hunk
add_hunk: "*** Add File: " filename LF add_line+
delete_hunk: "*** Delete File: " filename LF
update_hunk: "*** Update File: " filename LF change_move? change?
filename: /(.+)/
add_line: "+" /(.*)/ LF -> line
change_move: "*** Move to: " filename LF
change: (change_context | change_line)+ eof_line?
change_context: ("@@" | "@@ " /(.+)/) LF
change_line: ("+" | "-" | " ") /(.*)/ LF
eof_line: "*** End of File" LF
%import common.LF
```

Paths are relative to the turn cwd; absolute paths must be inside the
workspace.

### 5.2 Parsing and application (`apply-patch` crate)

A port of Codex `codex-rs/apply-patch`, usable both in the runner and in tests:

1. Parse to `Vec<Hunk>`; lenient mode accepts a patch wrapped in a heredoc
   (`apply_patch <<'EOF' … EOF`) and missing final newline.
2. For each update hunk, read the file, split into lines, and for each chunk:
   locate the `@@` context line if present, then locate the old lines with
   `seek_sequence` starting at the current cursor, trying in order:
   exact match → match ignoring trailing whitespace → match ignoring leading
   and trailing whitespace → match after Unicode punctuation/space
   normalization (curly quotes, dashes, non-breaking spaces). With
   `*** End of File`, search from the end first.
3. Apply replacements in order; the cursor advances so chunks must be
   sequential.
4. Compute all new contents in memory first. If any hunk fails, nothing is
   written (Codex writes per file; we make the whole patch atomic within the
   runner by writing temp files and renaming after all hunks succeed).
5. Preserve the file's existing line endings and trailing-newline state.

### 5.3 Safety

Before application, the control plane runs `assess_patch_safety` (Codex
`core/src/safety.rs`):

- Rejects empty patches.
- Collects every source and move-destination path; each must be inside a
  writable root of the sandbox policy after canonicalization by the runner
  (symlinks resolved). Hard links are not trusted to stay inside the root, so
  application still happens inside the inner sandbox.
- Result: `AutoApprove` (all paths writable and policy permits), `AskUser`, or
  `Reject(reason)`. Combined with approval policy as in §6.2.

### 5.4 Events

`FileChange` item: `{changes: [{path, kind: add|delete|update{move_path?}, unified_diff}], status}`.
`PatchApplyBegin` → (approval) → `PatchApplyEnd {success, stdout, stderr}`.
`TurnDiff` updates after each successful patch (agent-loop.md §2.5).

## 6. Approvals

### 6.1 Policy

```rust
enum AskForApproval {
    UnlessTrusted,                        // ask for everything not allowed by exec policy
    OnRequest,                            // sandboxed runs proceed; ask on escalation requests
    Granular(GranularApprovalConfig),
    Never,                                // never ask; anything that would ask is denied
}

struct GranularApprovalConfig {
    sandbox_approval: bool,      // may ask to escalate out of sandbox
    rules: bool,                 // exec-policy Prompt decisions ask (else deny)
    request_permissions: bool,
    mcp_elicitations: bool,
}

enum ReviewDecision {
    Approved,
    ApprovedForSession,                              // same command prefix, this thread only
    ApprovedExecpolicyAmendment { prefix: Vec<String> },  // persist an allow rule (user rules)
    NetworkPolicyAmendment { host: String, scope: AmendScope },
    Denied { reason: Option<String> },
    TimedOut,
    Abort,                                           // deny and interrupt the turn
}
```

### 6.2 Decision table for `exec_command`

| Exec policy | Approval policy | Sandbox override requested | Result |
|---|---|---|---|
| Forbidden | any | any | deny, reason to model |
| Allow | any | no | run sandboxed |
| Allow | not Never | yes | ask |
| Prompt | Never, or Granular with `rules = false` | any | deny |
| Prompt | otherwise | any | ask |
| no match | UnlessTrusted | any | ask |
| no match | OnRequest / Granular | no | run sandboxed |
| no match | OnRequest / Granular(`sandbox_approval`) | yes | ask |
| no match | Never | yes | deny |
| no match | Never | no | run sandboxed |

An `Allow` decision affects approval only; it never removes the sandbox. If the
sandbox cannot be established, the command fails closed with
`sandbox_unavailable` (never runs unsandboxed).

Patch approvals follow §5.3 combined with the same policy columns.

### 6.3 Approval broker

- An `ApprovalRequest { id, thread_id, turn_id, agent_path, kind, payload,
  policy_version, sandbox_profile, cwd, created_at, expires_at }` is appended
  to the log, and the turn status becomes `awaiting_approval`.
- `kind`: `Exec { argv, cwd, reason, proposed_prefix }`,
  `Patch { changes, grant_root? }`, `Network { host, port, protocol }`,
  `McpTool { server, tool, args }`, `McpElicitation { server, schema }`.
- The decision is bound to the exact request id; resolving a request whose
  thread, policy version or sandbox profile has since changed is rejected
  (`409 approval_stale`).
- Only the thread owner can resolve. Resolution is idempotent per request id.
- `ApprovedForSession` adds `(argv prefix, cwd, sandbox profile)` to the
  thread's in-memory session cache, persisted in the log so it survives
  restart; it never applies to other threads or users.
- `ApprovedExecpolicyAmendment` appends a `prefix_rule(decision="allow")` to
  the user's rule set (§8.3) with provenance (thread, request id, time).

### 6.4 Timeouts and unattended runs

Pending approvals hold the turn indefinitely while the user is attached. When
no client has been attached for `approval_unattended_timeout` (default 30 min),
the request resolves `TimedOut` and the model is told the action was not
approved. Push notifications (Android) are sent on approval requests
(ui.md §7.2).

## 7. Sandbox

### 7.1 Policy

```rust
enum SandboxPolicy {
    ReadOnly { network: NetworkMode },
    WorkspaceWrite { writable_roots: Vec<RunnerPath>, network: NetworkMode, allow_tmp: bool },
    DangerFullAccess,               // operator-only; still inside the runner container
}

enum NetworkMode { None, Proxy { allow: Vec<HostPattern> }, Full }
```

The runner container (architecture.md §1) is the tenant boundary. The inner
sandbox is defense in depth between the agent's commands and the runner's own
state (tokens, sockets, other worktrees).

### 7.2 Linux enforcement (per command)

Matching Codex `linux-sandbox`:

- bubblewrap with a new user, mount and PID namespace.
- `/` bind-mounted read-only; writable roots bound read-write on top;
  `.git/hooks`, `.git/config` and `.agents/` inside writable roots re-bound
  read-only (a model must not plant hooks that run with the git credential
  helper).
- Runner state (`/run/agent-runner`, credential helper socket, other users'
  worktrees) not mounted at all.
- `PR_SET_NO_NEW_PRIVS`, seccomp filter denying `ptrace`, `mount`, `bpf`,
  kernel module and keyring syscalls; in `None` and `Proxy` network modes, a
  new network namespace with no interfaces except, in `Proxy` mode, a bridge to
  the egress proxy socket; creation of new `AF_UNIX` sockets denied in `Proxy`
  mode so the command cannot reach the runner's sockets.
- Resource limits: cgroup per command (CPU weight, memory 4 GiB default,
  pids 512), wall-clock limit per §4.2.

If bwrap is missing or user namespaces are unavailable the runner refuses
sandboxed execution and reports `sandbox_unavailable` at `Hello` time; the
control plane marks the workspace degraded and disables exec tools.

### 7.3 Network egress

All runner egress goes through a per-runner proxy enforcing the workspace's
network policy:

- Host allowlist globs normalized (lowercase, IDNA, trailing dot, ports).
- Resolved addresses re-checked against the private/link-local/metadata deny
  list after DNS resolution (rebinding protection), as `agent_egress.rs` does
  today for agent connections.
- Default allowlist for `Proxy` mode: package registries the operator
  configures (crates.io, npm, PyPI) and `github.com` only through the git
  credential helper path (workspaces-git.md §4).
- A blocked request produces a `Network` approval request when the policy can
  ask; `NetworkPolicyAmendment` adds the host for the thread or the workspace.

### 7.4 Shell environment policy

Codex `ShellEnvironmentPolicy`, applied by the runner after `env_clear()`:

```rust
struct ShellEnvironmentPolicy {
    inherit: Inherit,                  // Core (default here) | All | None
    ignore_default_excludes: bool,     // default false
    exclude: Vec<Glob>,
    set: BTreeMap<String, String>,
    include_only: Vec<Glob>,
}
```

1. Start from the runner's environment according to `inherit` (`Core` = `HOME`,
   `PATH`, `SHELL`, `USER`, `LANG`, `LC_*`, `TERM`, `TMPDIR`).
2. Unless `ignore_default_excludes`, drop names matching `*KEY*`, `*SECRET*`,
   `*TOKEN*` (case-insensitive).
3. Drop `exclude` matches. Insert `set`. Apply `include_only` if non-empty.
4. Always set `CODEX_SANDBOX`-equivalent markers: `AGENT_SANDBOX=<profile>`,
   `AGENT_THREAD_ID`, and `GIT_TERMINAL_PROMPT=0`.

Codex defaults `inherit` to `All`; here `Core` is the default because the runner
environment is service configuration, not a user's shell. Filtering is hygiene,
not a secret boundary: the runner never places user credentials in its own
environment (workspaces-git.md §4).

## 8. Exec policy

### 8.1 Language

The Codex `execpolicy` Starlark subset, reused as a crate port:

```python
prefix_rule(
    pattern = ["git", ["push", "fetch"]],    # list element = alternatives
    decision = "prompt",                     # allow | prompt | forbidden
    justification = "Network git operations need review",
    match = [["git", "push", "origin", "main"]],     # examples that must match (validated at load)
    not_match = [["git", "status"]],                 # examples that must not match
)
network_rule(host = "*.crates.io", decision = "allow")
host_executable(name = "cargo", paths = ["/usr/local/cargo/bin/cargo"])
```

Only these builtins are available; no loops, loads or I/O.

### 8.2 Evaluation

- The command string is parsed into one or more argv sequences. Simple
  `bash -lc "<script>"` forms are decomposed into pipelines and `&&`/`||`/`;`
  lists with a conservative parser; constructs it cannot parse (subshells,
  command substitution, here-docs other than `apply_patch`, `eval`) are
  evaluated as a single opaque command that matches only rules with the
  `bash` prefix and otherwise yields no match.
- Each argv is matched against all rules; the strictest decision across all
  matching rules and all argv sequences wins
  (`forbidden > prompt > allow`).
- Built-in safe list (Codex `is_known_safe_command`): read-only commands such as
  `ls`, `cat`, `head`, `tail`, `wc`, `grep`, `rg`, `find` without
  `-exec`/`-delete`, `git status|log|diff|show|branch` (without mutating
  flags), `sed -n` — treated as `allow`.
- Built-in dangerous list: `rm -rf /`-like targets outside the workspace,
  `git push --force`, `git reset --hard` outside a worktree, `sudo`, `curl … | sh`
  — treated as `prompt`.

### 8.3 Rule layers

Operator rules (`/etc/chatbot/agent-rules/*.rules`) > user rules (encrypted in
the control plane, editable in settings and amended by approvals) > trusted
repository rules (`.agents/rules/*.rules`, may only add `prompt`/`forbidden`).
The strictest decision across layers wins, so a repository cannot allow what
the operator forbids. Each `TurnContext` records the `PolicyVersion` (hash of
effective rules).

## 9. MCP

### 9.1 Configuration

```rust
struct McpServerConfig {
    name: String,
    transport: McpTransport,              // Stdio { command, args, env, cwd } (runs in the runner)
                                          // | StreamableHttp { url, headers, bearer_token_ref }
    enabled: bool,
    required: bool,                       // thread start fails if it cannot connect
    startup_timeout: Duration,            // default 10 s
    tool_timeout: Duration,               // default 60 s
    supports_parallel_tool_calls: bool,   // default false
    enabled_tools: Option<Vec<String>>,
    disabled_tools: Vec<String>,
    approval: McpApprovalMode,            // Auto | Ask | AskWrites (uses tool annotations readOnlyHint)
    privacy: PrivacyLevel,                // destination class for HTTP servers; stdio servers inherit the workspace
    oauth: Option<McpOAuthConfig>,
}
```

Sources: operator config, user settings, trusted repository `.agents/mcp.toml`.
Stdio servers run in the runner under the inner sandbox with the workspace's
network policy. HTTP servers are called from the runner's egress proxy and are
subject to privacy eligibility like any destination.

### 9.2 Tools and resources

- Server tools are registered as `mcp__<server>__<tool>` with the server's
  JSON Schema (sanitized: unsupported keywords removed, schema size capped at
  64 KiB per tool).
- `list_mcp_resources {server?, cursor?}`, `list_mcp_resource_templates
  {server?, cursor?}`, `read_mcp_resource {server, uri}`.
- Output: `Wall time: N.NNNN seconds\nOutput:\n<content>`; structured content is
  kept as content items; images become `InputImage`.
- Elicitation requests from a server become `McpElicitation` approval requests
  rendered as forms.

### 9.3 Exposing the agent as an MCP server

Out of scope for phase 1. The runner protocol already models tool calls, so a
later phase can expose workspace tools to external MCP clients.

## 10. Dynamic client tools

A client (web UI, Android) may register tools for a thread, e.g.
`show_on_map` or `read_clipboard`. They are `Function` specs whose calls are
forwarded to the client as `ClientToolCall` events and answered with
`POST /threads/{id}/client_tool_results/{call_id}`. If no client answers within
60 s, the output is `"client unavailable"`. Client tools are never parallel-safe.
