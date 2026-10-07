# Harness Adapters

Wrapping third-party agent harnesses (Codex, Claude Code, OpenCode, ACP agents,
arbitrary terminal programs) so they appear as threads with the same items,
approvals and event stream as native threads.

Harnesses are a bridge. They exist for subscriptions whose terms require the
vendor's own client, and to get mature tools before the native loop has them.
Every capability built here must also make sense for the native runtime, so
the UI and storage never depend on a specific harness.

## 1. Principles

1. **Structured protocol first.** Use each harness's machine interface
   (app-server JSON-RPC, stream-json, HTTP/SSE, ACP). A PTY is used only for
   harnesses without one, or as a side panel for interactive login and
   debugging.
2. **Normalize stable concepts only.** Map what maps (messages, reasoning,
   commands, file changes, tool calls, approvals, turn status). Forward the rest
   as `Unknown` items with the raw payload. Never synthesize events the harness
   did not report.
3. **Advertise capabilities, never fake them.** Unsupported actions are hidden
   in the UI, not emulated with prompt text.
4. **The harness owns its model history.** The control plane stores the
   normalized event log for display, search and replay; it does not try to
   reconstruct or replay the harness's prompt.
5. **Harnesses run in the runner.** Same container, same workspace, same
   egress proxy. The harness's own process tree is supervised, not inner-sandboxed
   by default (most harnesses apply their own sandbox to the commands they run;
   ours wraps the whole harness when the harness has none, §2.4).

## 2. Adapter interface

### 2.1 Trait

Runs inside `agent-runner`; the control plane talks to it via `Harness*` runner
frames (architecture.md §3).

```rust
#[async_trait]
trait HarnessAdapter: Send + Sync {
    fn kind(&self) -> RuntimeKind;
    async fn probe(&self, env: &RunnerEnv) -> HarnessProbe;   // installed? version? authenticated? capabilities

    async fn start_session(&self, req: StartSession) -> Result<HarnessSession, HarnessError>;
    async fn resume_session(&self, req: ResumeSession) -> Result<HarnessSession, HarnessError>;
}

#[async_trait]
trait HarnessSession: Send {
    fn capabilities(&self) -> &HarnessCapabilities;
    async fn send_turn(&mut self, input: Vec<UserInput>, settings: TurnSettings) -> Result<(), HarnessError>;
    async fn steer(&mut self, input: Vec<UserInput>) -> Result<(), HarnessError>;
    async fn interrupt(&mut self) -> Result<(), HarnessError>;
    async fn answer(&mut self, request: HarnessRequestId, answer: HarnessAnswer) -> Result<(), HarnessError>;
    async fn reconcile(&mut self) -> Result<Vec<NormalizedEvent>, HarnessError>; // after reconnect/restart
    async fn close(&mut self) -> Result<(), HarnessError>;
    fn events(&mut self) -> BoxStream<'static, NormalizedEvent>;
}

struct StartSession {
    thread_id: ThreadId,
    cwd: RunnerPath,
    settings: TurnSettings,          // model, effort, approval/permission mode mapped per harness
    system_prompt_append: Option<String>,
    gateway: Option<GatewayBinding>, // §9
    mcp_servers: Vec<McpServerConfig>,
}
```

### 2.2 Capabilities

```rust
struct HarnessCapabilities {
    streaming_deltas: bool,
    reasoning: bool,
    persistent_sessions: bool,     // harness can resume its own session after restart
    steer: bool,
    interrupt: bool,
    approvals: ApprovalSupport,    // None | Structured | ModeOnly (harness enforces a mode; no per-call prompts)
    user_questions: bool,
    structured_tool_events: bool,
    file_change_events: bool,      // per-file diffs reported by the harness
    images_in: bool,
    fork: bool,
    usage: UsageSupport,           // Reported | Estimated | None
    model_selection: bool,
    gateway_routable: bool,        // can be pointed at the provider gateway (§9)
    terminal_view: bool,           // a live PTY of the harness is available
}
```

The UI reads capabilities from the thread's `ThreadStarted` event and from
`HarnessProbe` in the runtime picker.

### 2.3 Normalized events

Adapters emit `NormalizedEvent`, which the control plane turns into
`ThreadEvent`s (`events-and-storage.md` §2) with `origin = adapter:<kind>`:

```rust
struct NormalizedEvent {
    body: EventBody,                        // the same enum native threads use
    provider_ids: ProviderIds,              // { session, turn, item, request } as the harness named them
    raw: Option<BoundedJson>,               // original payload, ≤ 16 KiB, secrets redacted
    occurred_at: Option<Timestamp>,         // harness timestamp; receipt time otherwise
}
```

Item ids are minted by the adapter (`events-and-storage.md` §1.1) and mapped
from provider ids in a per-session table so deltas for the same provider item
land on the same `item_id`.

### 2.4 Process supervision

- Each harness session is a child process group of `agent-runner`, started with
  `HOME=/work/.agent/harness/<kind>/home`, the workspace cwd, a scrubbed
  environment (tools.md §7.4 with `inherit = Core`) plus the harness's own
  variables, and the egress proxy.
- Harnesses with their own sandbox for tool execution (Codex, Claude Code with
  sandbox settings) run directly in the runner container. Harnesses without one
  run under the inner sandbox with the thread's sandbox policy, writable roots
  = worktree + harness home.
- stdout is the protocol channel for stdio harnesses; stderr goes to a bounded
  ring (256 KiB) surfaced as a `Notice` on failure.
- JSONL decoding: accumulate bytes to `\n`, max line 8 MiB, malformed lines
  become `Warning` events with a sample, never text deltas.
- Shutdown: protocol-level close → SIGTERM → 5 s → SIGKILL, then reap.
- A harness process that exits without a terminal turn event completes the
  turn with `Failed(RunnerUnavailable)` plus a notice containing the exit
  status; with `persistent_sessions`, the next turn resumes the harness session.

### 2.5 Approvals bridge

Harness permission requests become `ApprovalRequested` events with
`kind` mapped (exec, patch, network, MCP, other). The user's decision is sent
back through `answer`. Decisions that the harness cannot represent are reduced
to its closest supported option and the reduction is shown in the item (e.g.
`approved_for_session` → OpenCode `always`). Exec-policy rules (tools.md §8)
are not enforced on harness commands beyond what the harness reports; the
runtime picker labels this.

## 3. Codex (`codex app-server`)

### 3.1 Transport

`codex app-server` over stdio (newline-delimited JSON, JSON-RPC shape without
the `jsonrpc` field). The WebSocket transport is not used: it rejects requests
with an `Origin` header and is documented as experimental; the adapter owns
the only connection.

Startup: `initialize { clientInfo: {name: "chatbot-rust", version}, capabilities: {experimentalApi: false} }`
→ `initialized` notification. Methods used:

| Purpose | Method |
|---|---|
| new thread | `thread/start { cwd, model?, approvalPolicy, sandbox, baseInstructions?, developerInstructions? }` |
| reopen | `thread/resume { threadId }` |
| fork | `thread/fork { threadId, … }` |
| history | `thread/read`, `thread/turns/list` (reconcile) |
| turn | `turn/start { threadId, input, model?, effort?, approvalPolicy?, sandboxPolicy?, outputSchema? }` |
| steer | `turn/steer { threadId, turnId, input }` |
| interrupt | `turn/interrupt { threadId, turnId }` |

The adapter pins a Codex version per runner image and generates its Rust DTOs
from that version's exported JSON Schema (`codex app-server generate-json-schema`),
ignoring unknown fields.

### 3.2 Server requests

| Codex request | Normalized |
|---|---|
| `item/commandExecution/requestApproval` | `ApprovalRequested { kind: Exec }` |
| `item/fileChange/requestApproval` | `ApprovalRequested { kind: Patch }` |
| `item/permissions/requestApproval` | `ApprovalRequested { kind: Network or Other }` |
| `item/tool/requestUserInput` | `UserInputRequested` |
| `item/tool/call` (dynamic tools) | `ClientToolCall` when the tool was registered by our client; otherwise error |
| `mcpServer/elicitation/request` | `ApprovalRequested { kind: McpElicitation }` |

Decisions map 1:1 to Codex `ReviewDecision` (`accept`, `acceptForSession`,
`decline`, `cancel`, amendments) because our `ReviewDecision` was modeled on it
(tools.md §6.1).

### 3.3 Item mapping

| Codex notification / `ThreadItem` | Our item / event |
|---|---|
| `turn/started`, `turn/completed { turn.status }` | `TurnStarted`, `TurnCompleted` (`completed`/`interrupted`/`failed` 1:1) |
| `UserMessage` | `UserMessage` |
| `AgentMessage` + `item/agentMessage/delta` | `AgentMessage` + `AgentMessageDelta` |
| `Reasoning` + `item/reasoning/summaryTextDelta` | `Reasoning` + `ReasoningDelta` |
| `CommandExecution` + `item/commandExecution/outputDelta` | `CommandExecution` + `CommandOutputDelta` |
| `FileChange` + `item/fileChange/outputDelta` | `FileChange` |
| `turn/diff/updated` | `TurnDiff { exact: true }` |
| `Plan` / `turn/plan/updated` | `Plan` (`ItemUpdated`) |
| `McpToolCall` | `McpToolCall` |
| `DynamicToolCall` | `ToolCall` |
| `WebSearch` | `WebSearch` |
| `CollabAgentToolCall`, `SubAgentActivity` | `SubagentCall` (child threads are not mirrored as our threads in phase 1; shown inline) |
| `ContextCompaction` | `ContextCompaction` |
| `EnteredReviewMode` / `ExitedReviewMode` | `Review` |
| `thread/tokenUsage/updated` | `TokenCount` |
| `account/rateLimits/updated` | `RateLimits` |
| `error`, `warning`, `configWarning` | `Error` / `Warning` |
| anything else | `Unknown` |

The completed item replaces the started item (both systems treat completion as
authoritative).

### 3.4 Authentication and model routing

- **ChatGPT subscription**: the user runs `codex login --device-auth` in a
  harness terminal (§7) inside their runner; credentials stay in that harness
  home. Model traffic goes from the runner to OpenAI directly; the thread is
  `non_private`.
- **API key / gateway**: Codex is configured with a `model_providers.gateway`
  entry pointing at the provider gateway (§9) with `wire_api = "responses"`;
  privacy follows the routed provider.

Rollout files Codex writes stay in the harness home; `thread/read` is the
reconcile path.

## 4. Claude Code (`claude -p`)

### 4.1 Process model

One process per turn (Claude Code's headless mode is turn-oriented):

```
claude -p --output-format stream-json --input-format stream-json --verbose
       --include-partial-messages
       --session-id <uuid>        (first turn)  |  --resume <session_id>  (later turns)
       --permission-mode <default|acceptEdits|plan|bypassPermissions>
       --permission-prompt-tool mcp__chatbot__approve
       --model <model>?  --append-system-prompt <text>?
       --mcp-config <runner-generated json>
```

- Input is written as stream-json user messages on stdin, which also allows
  sending additional user messages while the process runs (steering, when the
  installed version supports it; probed at startup).
- `--permission-prompt-tool` points at a small MCP server hosted by the
  runner (`chatbot` server, tool `approve`) that forwards each permission
  request to the control plane as an `ApprovalRequested` and blocks until the
  decision arrives. This gives structured per-call approvals.
- Interrupt: SIGINT to the process group; Claude Code persists the
  interrupted turn so `--resume` continues.

### 4.2 Authentication

- **Subscription login** (Pro/Max): the user runs `claude /login` (or
  `claude setup-token`) in a harness terminal inside their own runner. The
  login stays in their harness home and is used only by their own sessions.
  Anthropic's terms do not allow third-party products to offer claude.ai login
  to other users; the operator therefore enables subscription mode only for
  the operator's own account, and the runtime picker never offers another
  user the operator's login (architecture.md §5.5).
- **API key**: provided by the user (sealed per user) or via the gateway with
  `ANTHROPIC_BASE_URL` pointing at the gateway's Messages endpoint (§9).
  `--bare` is used in this mode for deterministic startup.

### 4.3 Event mapping (stream-json)

| stream-json | Our item / event |
|---|---|
| `system` / `init` | `ThreadSettingsChanged` (model, tools, MCP servers); MCP startup errors → `Warning` |
| `stream_event` text deltas | `AgentMessageDelta` |
| `stream_event` thinking deltas | `ReasoningDelta` |
| `assistant` message, `text` block | `AgentMessage` completed |
| `assistant` message, `thinking` block | `Reasoning` completed |
| `tool_use` `Bash` + matching `tool_result` | `CommandExecution` (command, output, exit code parsed from result) |
| `tool_use` `Edit`/`MultiEdit`/`Write` + result | `FileChange` (diff computed by the runner from before/after content captured on `tool_use`) |
| `tool_use` `Read`/`Glob`/`Grep`/`LS` | `ToolCall` |
| `tool_use` `WebSearch`/`WebFetch` | `WebSearch` / `ToolCall` |
| `tool_use` `TodoWrite` | `Plan` (`ItemUpdated`) |
| `tool_use` `Task` (subagent) + messages with `parent_tool_use_id` | `SubagentCall`, child messages nested under it |
| `tool_use` `mcp__*` | `McpToolCall` |
| `result` (`subtype: success \| error_*`, `usage`, `total_cost_usd`) | `TokenCount` (usage `Reported`, cost marked estimate) + `TurnCompleted` |
| process exit without `result` | `TurnCompleted { Failed }` |

### 4.4 Capabilities

`streaming_deltas`, `reasoning`, `persistent_sessions`, `interrupt`,
`approvals: Structured` (via permission prompt tool), `structured_tool_events`,
`file_change_events` (runner-computed), `images_in`, `usage: Reported`,
`model_selection`, `gateway_routable` (API-key mode only), `terminal_view`.
`steer` depends on version probe. `fork` via `--fork-session`.

## 5. OpenCode (`opencode serve`)

### 5.1 Placement

Two modes:

- **Runner-local** (default): `opencode serve --hostname 127.0.0.1 --port <ephemeral>`
  inside the runner with `OPENCODE_SERVER_PASSWORD` set to a per-boot secret.
  Only the adapter talks to it.
- **Remote connection**: an existing `agent_connections` record (the current
  OpenCode connector). The control plane talks to it through the existing
  egress validator (DNS pinning, no redirects, no proxy), extended to streaming
  bodies with the validation held for the stream's lifetime. Remote OpenCode
  works on the remote host's files, not a workspace; such threads have no
  workspace binding and are `non_private`.

The current health-check-only connection gains: session create/list, async
prompt, abort, event subscription and permission answers.

### 5.2 API subset

Discovered from the server's `/doc` OpenAPI document at probe time and checked
against the pinned version:

| Purpose | Route |
|---|---|
| health | `GET /global/health` |
| session | `POST /session`, `GET /session/:id`, `POST /session/:id/fork` |
| turn | `POST /session/:id/prompt_async` (204) |
| interrupt | `POST /session/:id/abort` |
| history | `GET /session/:id/message` (`{info, parts}[]`) |
| events | `GET /event` (SSE; first event `server.connected`) |
| permissions | `POST /session/:id/permissions/:permissionID { response: once \| always \| reject }` |
| diff | `GET /session/:id/diff` |

Subscribe to `/event` before `prompt_async` to avoid missing early events. On
reconnect, refetch `/session/:id/message` and reconcile by message/part ids.

### 5.3 Mapping

| OpenCode | Our item / event |
|---|---|
| `message.updated` (assistant), `message.part.updated` `text` | `AgentMessage` / `AgentMessageDelta` (parts carry full text; the adapter diffs snapshots into deltas) |
| part `reasoning` | `Reasoning` |
| part `tool` with `bash` | `CommandExecution` |
| part `tool` with `edit`/`write`/`patch` | `FileChange` |
| other `tool` parts | `ToolCall` / `McpToolCall` |
| `todo.updated` | `Plan` |
| `permission.updated` | `ApprovalRequested` |
| `session.idle` | `TurnCompleted { Completed }` |
| `session.error` | `TurnCompleted { Failed }` |

## 6. ACP agents (Gemini CLI, Hermes, others)

- Launch `gemini --acp`, `hermes acp`, or a configured command over stdio.
- `initialize` with `protocolVersion` and client capabilities. The runner
  offers `fs` and `terminal` client capabilities for ACP v1 agents (served
  inside the workspace through the same executors as native tools, under the
  inner sandbox); for v2 agents these are not offered and client tools are
  provided through MCP instead.
- `session/new { cwd, mcpServers }`, `session/load` when `loadSession` is
  advertised, `session/prompt`, `session/cancel`.
- `session/update` notifications: `agent_message_chunk` → `AgentMessageDelta`,
  `agent_thought_chunk` → `ReasoningDelta`, `tool_call` / `tool_call_update`
  → `ToolCall` or `CommandExecution` (when `kind = execute`) or `FileChange`
  (when content includes a diff), `plan` → `Plan`.
- `session/request_permission` → `ApprovalRequested` with the agent's options
  as the decision choices.
- The prompt response's `stopReason` (`end_turn`, `cancelled`, `max_tokens`,
  `refusal`, …) → `TurnCompleted`.

ACP version and capabilities are negotiated per launch and recorded on the
thread; an agent request for an unadvertised capability returns a JSON-RPC
error instead of hanging.

## 7. Terminals (PTY)

### 7.1 Uses

1. **Terminal runtime**: a thread whose runtime is a terminal program (any TUI
   agent without a machine interface). The thread has one `TerminalSession`
   item; there are no structured turns.
2. **Harness side terminal**: an interactive terminal in the harness's home and
   cwd for login (`codex login`, `claude /login`), configuration, or inspecting
   a session. Available for every harness with `terminal_view`.
3. **Workspace shell**: a plain shell in a workspace for the user.

### 7.2 Mechanics

- The runner allocates PTYs with `portable-pty`, default 120×40, `TERM=xterm-256color`.
- Bytes flow over the terminal WebSocket (`events-and-storage.md` §6.4) as
  binary frames; resize and exit status as text frames. Never through UTF-8
  text APIs.
- Backpressure: the runner buffers up to 1 MiB per terminal for a slow client,
  then pauses reading from the PTY master (the program blocks on write) rather
  than dropping bytes.
- Detach/attach: the runner keeps a 2 MiB scrollback ring per terminal; on
  attach the client receives the ring first, then live bytes. Terminals keep
  running with no viewers until the program exits or the runner idles out.
- Recording: off by default. When enabled per terminal, output is stored as
  sealed asciicast v2 chunks in the event log blobs, so it inherits thread
  encryption. Input is never recorded.
- Multiple viewers see the same terminal; only one device holds the input
  lease at a time (taken by typing, shown in the UI).

### 7.3 Turn semantics for terminal runtimes

A terminal runtime has no turns; the UI shows the terminal as the thread body.
Prompt submission from the thread composer is typed into the terminal followed
by Enter, and labeled as such. No approvals or items are inferred from screen
content.

## 8. Terms of service constraints

| Harness | Mode | Allowed use in this design |
|---|---|---|
| Codex | ChatGPT login | The user's own login, used by their own sessions on a runtime they control. Not shared, not relayed as a general API. |
| Codex | API key / gateway | Any user, billed to the key owner. |
| Claude Code | claude.ai login | Operator's own account only. Third-party products may not offer claude.ai login or rate limits to other users without Anthropic's approval. |
| Claude Code | API key / Bedrock / Vertex | Any user, billed to the key owner. |
| OpenCode | its configured providers | Per provider terms. |
| Gemini CLI / Hermes | their configured providers or logins | Per provider terms; user's own login only. |

Rules enforced in code:

- A subscription-login harness home belongs to one user's runner and is never
  copied, mounted elsewhere or read by the control plane.
- No adapter exposes a harness as an OpenAI-/Anthropic-compatible API for other
  clients (no "codex-as-api" relay).
- The provider gateway never forwards traffic using a subscription login; it
  only uses configured API keys.
- Every subscription-backed thread is `non_private` and labeled with the
  account it runs under.

This table records the design constraint, not legal advice; each vendor's
current terms are checked when enabling a mode.

## 9. Gateway routing

Harnesses that accept a custom endpoint can use the control plane's provider
gateway (architecture.md §4) instead of their own provider credentials:

- The runner exposes `http://gateway.internal/v1` (Responses + Chat
  Completions) and `/anthropic/v1/messages`, forwarded over the runner
  protocol as `ModelRequest` frames, so the runner needs no network route to
  providers.
- Each harness session gets a bearer token valid only for that session's
  thread, its allowed models and its budget.
- The gateway applies privacy eligibility and usage accounting per request, so
  a gateway-routed harness thread can be `private` when the harness runs in a
  `private` workspace and routes only to eligible (e.g. local) providers.

## 10. Choosing a runtime

The runtime picker lists, per workspace: `native` (always), and each harness
whose `probe` reports installed and authenticated, with its capability icons,
privacy level and account label. A thread's runtime is fixed at creation;
switching runtime means a new thread (optionally seeded with a summary of the
old one through the native compaction prompt).
