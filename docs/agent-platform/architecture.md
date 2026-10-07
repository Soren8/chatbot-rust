# Architecture

## 1. Components

### 1.1 Control plane: `chatbot-server`

Owns everything that needs the user's identity, data key or privacy decision:

- authentication, CSRF, per-request data key, account and privacy policy;
- conversation, thread, turn and item APIs (`events-and-storage.md`);
- the encrypted event log and thread index;
- the **provider gateway**: the only component that calls model providers
  (§4). Runners never hold provider API keys;
- the approval broker: pending approvals are durable items answered through the
  control plane;
- the GitHub connection broker that mints short-lived, repository-scoped tokens
  (`workspaces-git.md`);
- the native agent loop when placed in-process (§6).

The webserver never mounts user workspaces, never runs user code and never
receives container-engine authority.

### 1.2 New crates

| Crate | Role | Depends on |
|---|---|---|
| `chatbot-agent-protocol` | Serde types shared by control plane and runner: thread/turn/item, events, tool specs, runner RPC, approvals | none |
| `chatbot-agent` | Native loop: session, task, turn, sampling, tool router, context assembly, compaction, subagents, hooks | protocol |
| `chatbot-providers` | Extracted provider layer with Chat Completions, Responses and Anthropic Messages tool-calling shapes and streaming parsers | protocol |
| `agent-runner` | Binary inside the user container: tool executors, PTY manager, sandbox launcher, harness adapters, git operations | protocol |
| `workspace-manager` | Privileged allocator for runner containers and volumes | protocol |
| `apply-patch` | Parser and applier for the patch grammar (`tools.md` §5), shared by runner and tests | none |
| `execpolicy` | Rule engine for command decisions (`tools.md` §8) | none |

`chatbot-core` keeps history and privacy primitives; the event log is a new
module under `chatbot-core/src/agent_log/` so it reuses `history/crypto.rs`.

### 1.3 Workspace manager

A separate privileged service on the agent host, reachable only from the
control plane over an authenticated channel (mTLS or a Unix socket with peer
credential checks). Its API is intentionally small:

| Call | Effect |
|---|---|
| `EnsureRunner { user_id, workspace_id, profile }` | Create or start the user's runner container with its volume, CPU/memory/pids limits and network policy. Returns a runner endpoint and a per-boot runner credential. |
| `StopRunner { workspace_id }` | Graceful stop; volumes kept. |
| `DeleteWorkspace { workspace_id }` | Remove container and volumes after the control plane confirms ownership and user intent. |
| `RunnerStatus { workspace_id }` | Running, stopped, starting, failed, resource usage. |

It never receives prompts, provider keys, history keys or GitHub tokens. Idle
runners stop after a configurable timeout (default 30 minutes with no active
turn and no attached terminal).

Deployments without an agent host keep full chat functionality; agent features
report `unavailable` instead of falling back.

### 1.4 Runner

One container per user workspace, running `agent-runner` as an unprivileged
user. It exposes the runner protocol (§3) to the control plane only. Inside it:

- **tool executors** for exec, PTY, `apply_patch`, filesystem reads, git, image
  viewing and MCP clients;
- **inner sandbox**: each model-initiated command runs under bubblewrap with
  seccomp and `PR_SET_NO_NEW_PRIVS` according to the turn's sandbox profile
  (`tools.md` §7). The container is the tenant boundary; the inner sandbox
  protects the workspace and the runner from the model;
- **harness adapters** that launch and supervise third-party agents
  (`harness-adapters.md`);
- **egress proxy** enforcing the network policy for sandboxed commands.

The runner keeps no durable state outside the workspace volume except a small
crash-recovery journal of in-flight tool calls (§3.4).

## 2. Trust boundaries

| Boundary | Trusted side | Untrusted side | Enforcement |
|---|---|---|---|
| Browser ↔ control plane | control plane | browser | session, CSRF, per-request key, owner checks |
| Control plane ↔ workspace manager | both (operator-owned) | — | mTLS / peer creds; manager validates nothing about users beyond ownership tokens issued by the control plane |
| Control plane ↔ runner | control plane | runner (runs user and model code) | runner credential per boot; control plane validates every runner message against the active turn; runner cannot call control-plane APIs except the runner protocol |
| Runner ↔ inner sandbox | runner | model-issued commands | bwrap, seccomp, egress proxy, exec policy, approvals |
| Runner ↔ harness process | runner | third-party harness | process supervision, container limits, env scrubbing, no provider keys except the user's own harness credentials |
| Control plane ↔ providers | control plane | provider | privacy eligibility, egress validator |

A compromised runner can damage its own user's workspace and spend that user's
budget. It must not be able to read other users' data, the control plane's
keys or another runner's traffic. Container isolation on a dedicated agent host
is the starting point; it is not equivalent to per-user VMs for hostile
workloads, and the deployment decision is recorded in `roadmap.md`.

## 3. Runner protocol

Transport: one long-lived HTTP/2 or WebSocket connection initiated by the
control plane, carrying length-prefixed JSON frames. Both sides may originate
requests. Every frame:

```rust
struct RunnerFrame {
    id: FrameId,              // monotonically increasing per sender
    reply_to: Option<FrameId>,
    body: RunnerBody,
}
```

### 3.1 Control plane → runner

| Request | Purpose |
|---|---|
| `Hello { protocol_version, runner_credential }` | Handshake; runner answers with capabilities, tool inventory, OS, available sandboxes, installed harnesses. |
| `ToolCall { thread_id, turn_id, call_id, tool, input, env: EnvironmentSpec, deadline }` | Execute one tool. `EnvironmentSpec` carries cwd, sandbox profile, network policy, environment variables after policy filtering, and approval-granted overrides. |
| `ToolCancel { call_id }` | Cancel a running call. |
| `PtyWrite { session_id, bytes }`, `PtyResize`, `PtyKill` | Interactive terminal control. |
| `ReadContextFiles { cwd, project_root }` | Return `AGENTS.md` chain, skills catalog and git status for context assembly (`agent-loop.md` §6). |
| `Snapshot { worktree }` / `Restore { worktree, snapshot }` | Turn-level undo (`workspaces-git.md` §5). |
| `HarnessStart`, `HarnessInput`, `HarnessAnswer`, `HarnessStop` | Harness adapter control (`harness-adapters.md`). |
| `GitOp { op, token_ref }` | Clone/fetch/push with a broker-issued token (`workspaces-git.md`). |

### 3.2 Runner → control plane

| Message | Purpose |
|---|---|
| `ToolProgress { call_id, kind, payload }` | Output deltas, patch progress, PTY output. |
| `ToolResult { call_id, output: ToolOutput }` | Terminal result. |
| `ApprovalNeeded { call_id, request: ApprovalRequest }` | Raised by the runner when an exec-policy or sandbox check needs a decision that was not pre-granted. |
| `HarnessEvent { harness_session_id, envelope }` | Normalized harness events. |
| `ModelRequest { harness_session_id, request }` | Optional: a harness configured to use the control plane's provider gateway as its model endpoint (§4.3). |
| `Heartbeat { load, active_calls }` | Liveness every 5 s. |

### 3.3 Validation rules

- The control plane rejects any runner message whose `call_id`,
  `harness_session_id` or `pty session_id` it did not issue for that runner.
- Output frames are size-capped (64 KiB per frame, 1 MiB buffered per call,
  matching Codex's unified-exec output buffer) and rate-limited per call.
- The runner never sees conversation history. It receives exactly the inputs a
  tool needs.

### 3.4 Runner restart

The runner journals each accepted `ToolCall` and its PTY session ids in the
workspace volume. After a restart it reports `Hello` with `orphaned_calls`;
the control plane completes each orphaned call with the `runner_lost` outcome
so the model sees a tool error instead of a hang, and the turn continues or
fails according to `agent-loop.md` §8.

## 4. Provider gateway

### 4.1 Role

All model traffic from native threads and from gateway-backed harnesses flows
through one component in the control plane that:

1. resolves the requested model to a configured provider;
2. checks privacy eligibility of the thread against the destination **before**
   serializing any content, including retries, compaction requests, subagent
   requests and review requests;
3. applies budgets and per-user rate limits;
4. converts the internal prompt (`agent-loop.md` §4.1) to the provider wire
   format and normalizes the stream back to `ResponseEvent`s;
5. records token usage per thread, turn and step.

### 4.2 Wire formats

| Format | Used for | Notes |
|---|---|---|
| OpenAI Responses | OpenAI, Azure, compatible servers | Native reasoning items, `previous_response_id` optional, custom (grammar) tools for `apply_patch` |
| OpenAI Chat Completions | llama.cpp, vLLM, Ollama, xAI and other compatible endpoints | Function tools only; `apply_patch` is exposed as a JSON function with an `input` string |
| Anthropic Messages | Claude via API key | `tool_use`/`tool_result` blocks, thinking blocks with signatures that must round-trip, `cache_control` breakpoints |

Each provider config gains `wire_api`, `supports_parallel_tool_calls`,
`supports_reasoning_items`, `supports_custom_tools`, `context_window`,
`auto_compact_token_limit`, `max_output_tokens`, and a privacy level.

### 4.3 Harnesses and the gateway

Harnesses that accept an OpenAI- or Anthropic-compatible base URL (OpenCode,
Codex with a custom provider, Claude Code with an API key and base URL) can be
pointed at a gateway endpoint exposed to the runner as
`http://gateway.internal/v1` with a per-session bearer token. This keeps
provider keys in the control plane and lets privacy and budget checks apply to
harness traffic. Harnesses that must use a vendor subscription login bypass the
gateway; their sessions are `non_private` by construction (§5).

## 5. Privacy and key custody

### 5.1 Privacy of a thread

A thread inherits the privacy level of its conversation. The effective level of
any outbound action is the thread's level; every destination it reaches must be
eligible:

| Destination | Classified by |
|---|---|
| Model provider | provider config (existing) |
| Search backend | search config (existing) |
| Harness runtime | adapter config: `private` only when the harness itself is local and its model traffic is gateway-routed to eligible providers; vendor-login harnesses are `non_private` |
| MCP server | per-server config; remote MCP defaults `non_private` |
| Network egress from sandboxed commands | network policy; any unrestricted egress makes the turn's commands `non_private` destinations |
| GitHub push | the repository's visibility and the connection's account; pushing to a public repository is publication |

Subagents, review tasks and compaction requests inherit the parent thread's
level. A model instruction or tool argument can never lower it.

### 5.2 Workspace contents are not history

Files in a workspace live in the runner volume, outside client-key encryption.
A workspace therefore has its own privacy level, fixed at creation:

- `private` workspace: stored on an operator-controlled agent host with full
  disk encryption; usable by threads of any level;
- otherwise as configured. A `private` thread may only attach a `private`
  workspace.

The UI must state that workspace files are protected by host disk encryption
and tenant isolation, not by the user's data key.

### 5.3 Key custody for agent runs

The existing model (data key only in RAM for the duration of a request) is kept
for chat. Agent runs need the key for longer, because turns outlive requests and
must persist events. Three custody modes, chosen per thread:

| Mode | Behavior | Default for |
|---|---|---|
| **Attended** | The data key is held in control-plane RAM only while at least one authenticated view of the thread is attached or for a grace window (default 10 minutes) after the last view detaches, capped by the existing 30-minute generation lifetime extended to a configurable run lifetime (default 4 hours). When the key expires mid-turn, the turn pauses at the next step boundary with status `awaiting_key`; events produced meanwhile are buffered sealed under an ephemeral run key (§5.4). | `private` threads |
| **Run key** | A random per-thread run key encrypts the thread's event log. The run key is wrapped by the user's data key (stored) and, while a run is active, held in RAM. Unattended runs continue after the user leaves; on restart they wait for the user to unlock. | `standard` threads |
| **Server-managed** | The run key is wrapped by a server master key, enabling restart-resilient unattended runs. Matches the not-yet-implemented "Recoverable" mode in `design-privacy.md`. Requires explicit opt-in per thread. | none |

### 5.4 Ephemeral run key

Every active run has a random 256-bit run key held in RAM. Events are sealed
with it as they are appended (§ `events-and-storage.md` §4). When the user's data
key is present, the run key is wrapped with the data key and stored, so the log
remains readable later. If the process dies before the run key is wrapped,
events sealed only under it are unrecoverable by design; the thread shows
`events_lost` from the last wrapped checkpoint. This keeps the
"no standing key on disk" property for Private threads.

### 5.5 Credentials in the runner

- Provider keys never enter the runner; native threads and gateway-routed
  harnesses use the gateway.
- GitHub tokens enter only as short-lived, repository-scoped installation tokens
  passed per `GitOp` and held in memory by the git credential helper (§
  `workspaces-git.md` §4).
- A harness that needs the user's own vendor login (Claude subscription, ChatGPT
  login for Codex) stores that login inside the user's runner volume, created by
  the user through an interactive terminal session. The operator's own
  subscription credentials are never copied into any runner.
- Command environments are built from `ShellEnvironmentPolicy` (`tools.md` §7.4),
  which strips names matching `*KEY*`, `*SECRET*`, `*TOKEN*` by default.

## 6. Placement of the native loop

Two placements satisfy the boundaries above:

- **In-process (recommended first).** `chatbot-agent` runs inside
  `chatbot-server` as a task owned by `AppServices`, exactly like the current
  generation worker. It has direct access to the provider gateway and the event
  log, and calls tools through the runner protocol. Plaintext transcripts stay
  in the control plane, which already handles plaintext during requests.
- **Runner-hosted.** The loop runs inside the user's runner and calls the
  gateway for model requests. This isolates loop bugs from the webserver but
  moves plaintext history into the tenant container and requires shipping the
  transcript to the runner. Reserve for deployments where the control plane must
  stay small.

The loop's `ToolExecutor`, `ModelClient` and `EventSink` traits make placement
a wiring decision (`agent-loop.md` §2.5).

## 7. Scaling and restarts

- One control-plane process remains the initial deployment. The event log is
  the source of truth, so a restarted process can rebuild thread state, mark
  interrupted turns and resume runs whose key custody allows it.
- Per-thread ordering is enforced by a per-thread actor (single task owning the
  thread state); different threads proceed concurrently. No global mutex.
- Horizontal scaling would require moving thread ownership leases into shared
  storage; not in scope until a second control-plane instance is needed.
