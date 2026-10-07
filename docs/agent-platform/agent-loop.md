# Native Agent Loop

The `chatbot-agent` crate. Its structure follows Codex `codex-rs/core`
(`session/`, `tasks/`, `tools/`, `compact*`), adapted to a multi-user server:
every Codex singleton becomes per-thread state, local file I/O becomes runner
calls, and local rollout files become the encrypted event log.

Codex references are paths under `codex-rs/` for implementers who want to read
the original.

## 1. Object model

```
ThreadActor (one tokio task per loaded thread)
 ├── ThreadState            persistent: config snapshot, history, token usage, agent graph
 ├── ActiveTurn?            at most one
 │    ├── TurnContext       immutable per turn
 │    ├── TurnInputQueue    steering input received while the turn runs
 │    ├── CancellationToken
 │    └── SessionTask       Regular | Review | Compact
 ├── Mailbox                inter-agent messages and input that arrived between turns
 └── EventSink              append to log, then broadcast
```

### 1.1 Submission queue / event queue

As in Codex (`core/src/session/mod.rs`, `Submission`/`Op`), the actor accepts
operations on a bounded channel and emits events on another. HTTP handlers
never touch thread state directly.

```rust
struct Submission {
    id: SubmissionId,             // idempotency key from the client, or generated
    actor: UserId,                // checked against thread owner on entry
    op: Op,
    parent_turn_id: Option<TurnId>,
    trace: Option<TraceContext>,
}

enum Op {
    TurnInput { input: Vec<UserInput>, mode: InputMode, settings: Option<TurnSettings> },
    Steer { turn_id: TurnId, input: Vec<UserInput> },
    Interrupt { turn_id: Option<TurnId> },
    InterruptIfNoPendingInput { turn_id: TurnId },
    ResolveApproval { request_id: ApprovalId, decision: ReviewDecision },
    AnswerUserInput { request_id: RequestId, answers: Vec<Answer> },
    Compact,
    Review { target: ReviewTarget },
    UpdateThreadSettings(ThreadSettingsPatch),
    InterAgentMessage { from: AgentPath, items: Vec<UserInput>, trigger_turn: bool },
    RunUserShellCommand { command: String, timeout_ms: u64 },
    CleanBackgroundTerminals,
    Shutdown,
}

enum InputMode {
    StartOrQueue,   // start a turn if idle, otherwise append to the next-turn queue
    StartOrSteer,   // start if idle, otherwise inject into the running turn
}
```

Every op is validated (owner, thread status, privacy, settings bounds) before
any event is emitted. Rejected ops produce a typed error response, not events.

### 1.2 TurnContext and StepContext

Codex splits configuration into a per-turn snapshot and a per-sampling-request
snapshot so that settings changed mid-turn apply at the next step boundary and
never mid-request. Keep the split.

```rust
struct TurnContext {
    turn_id: TurnId,
    thread_id: ThreadId,
    agent_path: AgentPath,                 // "/root" or "/root/task_1/..."
    workspace: Option<WorkspaceRef>,
    cwd: RunnerPath,
    privacy: PrivacyLevel,                 // fixed for the turn; can only tighten
    approval_policy: AskForApproval,
    sandbox_policy: SandboxPolicy,
    exec_policy_version: PolicyVersion,
    shell_env_policy: ShellEnvironmentPolicy,
    collaboration_mode: CollaborationMode, // Default | Plan
    user_instructions: Option<String>,     // conversation system prompt / memory
    project_docs: ProjectDocs,             // AGENTS.md chain (§6.2)
    skills: SkillCatalog,
    features: FeatureSet,
    budget: TurnBudget,
    started_at: Timestamp,
}

struct StepContext {
    step_index: u32,
    model: ModelRef,                       // provider + model slug
    model_caps: ModelCapabilities,         // context window, tool kinds, parallel calls, reasoning
    reasoning_effort: Option<ReasoningEffort>,
    reasoning_summary: ReasoningSummaryMode,
    tools: Arc<ToolRouter>,                // built for this step (tools.md §2)
    output_schema: Option<JsonSchema>,
    compaction_limit: Option<u64>,
}
```

`TurnSettings` (model, effort, approval policy, sandbox profile) may be updated
for the active turn; updates take effect at the next `StepContext` capture.
Privacy can only become stricter mid-turn; loosening applies to future turns.

### 1.3 Tasks

```rust
#[async_trait]
trait SessionTask: Send + Sync {
    fn kind(&self) -> TaskKind;                // Regular | Review | Compact
    async fn run(
        self: Arc<Self>,
        thread: Arc<ThreadHandle>,
        ctx: Arc<TurnContext>,
        input: Vec<UserInput>,
        cancel: CancellationToken,
    ) -> Option<String>;                       // final agent message, if any
    async fn abort(&self, reason: TurnAbortReason);
}
```

- Exactly one task slot per thread. Spawning a task aborts the previous one with
  `TurnAbortReason::Replaced` (Codex `spawn_task`).
- `RegularTask` runs `run_turn` repeatedly while pending input remains after a
  turn completes, so queued user messages start the next turn without a round
  trip.
- `ReviewTask` runs a child thread with a review prompt, review model,
  `approval_policy = Never`, a read-only sandbox, and web search, subagents and
  collaboration tools disabled. Its result is posted to the parent as an
  `ExitedReviewMode` item.
- `CompactTask` performs manual compaction (§7).

## 2. The turn loop

### 2.1 `run_turn`

Pseudo-code; names mirror Codex `core/src/session/turn.rs`.

```text
run_turn(thread, ctx, input, cancel):
    emit TurnStarted { turn_id, model, settings_summary }
    run hooks: UserPromptSubmit(input)            -- may block or rewrite (§10)
    if thread.model_changed_since_last_turn and history.tokens > new_model.compaction_limit:
        compact(PreTurn, reason = ModelSwitch)
    elif history.tokens >= ctx.compaction_limit:
        compact(PreTurn, reason = ContextLimit)

    expand mentions in input:
        @file  -> attach file excerpt via runner fs read (bounded)
        $skill -> inject skill body (§6.3)
        mcp:// -> resolve resource
    record input items into history  (PersistContext::TurnStart, see §2.4)
    emit ItemCompleted(UserMessage)

    loop:
        if cancel.is_cancelled(): return abort(Interrupted)
        pending = turn_input_queue.drain() ++ mailbox.drain_for_turn()
        if pending not empty:
            record pending into history; emit UserMessage items (kind = steer)
        step = capture StepContext from current settings
        prompt = build_prompt(history.for_prompt(step.model_caps), step, base_instructions)

        result = run_sampling_request(prompt, step, cancel)   -- §3
        match result:
            Ok(SamplingOutcome { needs_follow_up, last_agent_message, usage }):
                accumulate usage; emit TokenCount
                if needs_follow_up and usage.total >= step.compaction_limit:
                    compact(MidTurn, reason = ContextLimit); continue
                if needs_follow_up: continue
                if turn_input_queue not empty: continue      -- steer arrived at the boundary
                stop = run hooks: Stop(last_agent_message)
                if stop.block_with(reason):
                    record reason as user-role continuation; continue
                break
            Err(ContextWindowExceeded):
                if not already_compacted_this_step: compact(MidTurn, ContextLimit); continue
                else fail turn with context_window_exceeded
            Err(UsageLimit | QuotaExceeded): fail turn with typed error
            Err(Interrupted): return abort(Interrupted)
            Err(other fatal): fail turn

    if post-turn compaction policy says so: compact(PostTurn)
    emit TurnDiff (final, §2.5)
    emit TurnCompleted { status: Completed, usage, last_agent_message }
```

A turn ends only when the model produces a response with no tool calls and no
new input is waiting. Tool calls always force a follow-up step because their
results must be shown to the model.

### 2.2 `build_prompt`

```rust
struct Prompt {
    instructions: String,              // base instructions for the model family (§6.1)
    input: Vec<ResponseItem>,          // normalized history
    tools: Vec<ToolSpec>,
    parallel_tool_calls: bool,         // model_caps.parallel && tools.any_parallel_safe
    reasoning: Option<ReasoningConfig>,
    output_schema: Option<JsonSchema>, // strict = true
    prompt_cache_key: ThreadId,        // stable per thread for provider prefix caching
    store: bool,                       // false unless the provider is the thread's chosen non-private store
}
```

History is projected through `for_prompt(model_caps)`, which applies the
normalization rules in §5.2 and drops modalities the model cannot accept.

### 2.3 Base instructions

One base instruction file per model family, versioned in the repository
(`chatbot-agent/prompts/*.md`), selected by `ModelRef`. Codex ships model-family
prompts (`core/prompt.md`, `gpt_5_codex_prompt.md` …); ours start from a common
core prompt that covers: autonomy and persistence, tool usage rules (prefer
`apply_patch` for edits, `exec_command` for reads/tests, never `cd` outside the
workspace), plan usage, final answer formatting for the web UI, and the
approval/sandbox contract for the current turn.

### 2.4 What is recorded

Two distinct streams come out of a turn (§ `events-and-storage.md`):

- **Model history** (`ResponseItem`s): exactly what is replayed to the model.
- **UI items and events**: what the user sees.

`record_items` writes model history and the corresponding UI events in one log
append so they cannot diverge. Items are recorded when they complete; deltas
are events only.

### 2.5 Turn diff tracking

As in Codex `TurnDiffTracker`: the runner reports, for each `apply_patch`, the
exact before/after content of each touched file. The tracker accumulates a
unified diff from the turn's baseline. Any file change not reported exactly
(e.g. a shell command that edited files) marks the tracker `inexact`; the final
diff is then computed by the runner with `git diff` against the turn-start
snapshot (`workspaces-git.md` §5). `TurnDiff` events carry the current diff
after each patch.

## 3. Sampling

### 3.1 `run_sampling_request`

```text
run_sampling_request(prompt, step, cancel):
    attempt = 0
    loop:
        match try_run_sampling_request(prompt, step, cancel):
            Ok(outcome) -> return outcome
            Err(Retryable(e, retry_after)) if attempt < max_stream_retries:
                attempt += 1
                delay = retry_after.unwrap_or(backoff(attempt))
                emit StreamError { message: e.summary, retrying_in: delay, attempt }
                sleep(delay) or cancel
                -- items already completed in the failed attempt stay recorded;
                -- the retried request uses the updated history
            Err(e) -> return Err(e)
```

Defaults, taken from Codex `model-provider-info`:

| Setting | Default | Codex constant |
|---|---|---|
| Request (connect) retries | 4 | `DEFAULT_REQUEST_MAX_RETRIES` |
| Stream retries | 5, max 100 | `DEFAULT_STREAM_MAX_RETRIES`, `MAX_STREAM_MAX_RETRIES` |
| Stream idle timeout | 300 s | `DEFAULT_STREAM_IDLE_TIMEOUT_MS` |
| Backoff | exponential with jitter from 5 s, capped at 60 s; server `retry-after` wins | `responses_retry.rs` |

Retryable: connect errors, 429 without a usage-limit body, 5xx, stream idle
timeout, truncated stream. Not retryable: 400, 401/403, context-window
exceeded, usage/quota limit, privacy rejection.

Retries never change the destination. Falling back to another provider is a
separate, explicit routing decision that re-runs eligibility.

### 3.2 `try_run_sampling_request`

```text
try_run_sampling_request(prompt, step, cancel):
    stream = gateway.stream(prompt, step)          -- normalized ResponseEvent stream
    in_flight = FuturesOrdered<ToolFuture>()
    active_item = None
    loop select:
        cancel -> drain_in_flight(abort); return Err(Interrupted)
        steer_preempt -> (§3.4)
        event = stream.next():
            Created -> nothing
            OutputItemAdded(item) -> emit ItemStarted(item projection)
            OutputTextDelta(d) -> emit AgentMessageDelta { item_id, d }
            ReasoningSummaryDelta(d, idx) -> emit ReasoningDelta { item_id, idx, d }
            ToolCallArgumentsDelta(d) -> emit ToolCallInputDelta (for apply_patch preview)
            OutputItemDone(item):
                record item into history
                if item is a tool call:
                    call = router.build_tool_call(item)?      -- unknown tool => error output
                    in_flight.push(dispatch(call))            -- parallel rules: tools.md §2.4
                    needs_follow_up = true
                else:
                    emit ItemCompleted(item projection)
            RateLimits(snapshot) -> emit RateLimits
            Completed { response_id, usage, end_turn } ->
                outputs = drain_in_flight()                   -- in call order
                record outputs into history (FunctionCallOutput / CustomToolCallOutput)
                return SamplingOutcome { needs_follow_up || end_turn == Some(false), usage, last_agent_message }
        tool_done = in_flight.next() -> emit tool item completion (output recorded at drain)
```

Tool futures start as soon as their call item is complete, before the response
finishes, so long tool calls overlap with model output. Outputs are recorded in
call order regardless of completion order, matching Codex `FuturesOrdered`.

### 3.3 Interrupt

`Op::Interrupt` cancels the turn token. In-flight tool calls receive
`ToolCancel`; exec sessions started with `tty` or background mode survive
(Codex: background terminals survive interrupt) and are listed for
`CleanBackgroundTerminals`. The turn records `TurnAborted { reason: Interrupted }`
and synthesizes `aborted` outputs for unanswered tool calls so history stays
well-formed.

### 3.4 Steering

`Op::Steer` appends to the active turn's `TurnInputQueue`. Default behavior:
the input is picked up at the next step boundary (after tool results). With
`preempt = true`, a `watch_user_input` subscription (subscribe first, then
check, to avoid lost wakeups) cancels the in-flight sampling request; tool
calls already dispatched finish, the partial assistant message is recorded as
incomplete, and the loop continues with `needs_follow_up = true` and the new
input appended. `InterruptIfNoPendingInput` interrupts only if the queue is
empty, so a "stop" racing with a steer cannot discard the steer.

## 4. Model client

### 4.1 Internal prompt items

```rust
enum ResponseItem {
    Message { id: Option<String>, role: Role, content: Vec<ContentItem>, phase: Option<MessagePhase> },
    Reasoning { id: String, summary: Vec<String>, content: Option<Vec<String>>, encrypted: Option<String>, provider_signature: Option<String> },
    FunctionCall { id: Option<String>, call_id: CallId, name: String, namespace: Option<String>, arguments: String },
    FunctionCallOutput { call_id: CallId, output: ToolOutputPayload },
    CustomToolCall { id: Option<String>, call_id: CallId, name: String, input: String },
    CustomToolCallOutput { call_id: CallId, output: ToolOutputPayload },
    WebSearchCall { id: Option<String>, action: WebSearchAction },
    Compaction { summary: String, replaced_through: Ordinal },
    Other(serde_json::Value),          // forward compatibility; never sent to providers that cannot accept it
}

enum ContentItem { InputText(String), InputImage(ImageRef), OutputText(String) }
enum ToolOutputPayload { Text(String), Items(Vec<ContentItem>) }
```

`arguments` stays a JSON string exactly as the model produced it; it is parsed
only by the tool handler. Reasoning items keep provider signatures/encrypted
content so they can be replayed verbatim to the same provider; they are dropped
when the next step uses a different provider.

### 4.2 Wire adapters

| Internal | Responses API | Chat Completions | Anthropic Messages |
|---|---|---|---|
| `Message{user}` | `message` input item | `{"role":"user"}` | `user` content blocks |
| `FunctionCall` | `function_call` | assistant `tool_calls[]` | `tool_use` block |
| `FunctionCallOutput` | `function_call_output` | `{"role":"tool","tool_call_id"}` | `tool_result` block in next user message |
| `CustomToolCall` (`apply_patch`) | `custom_tool_call` with grammar format | function `apply_patch {input: string}` | tool `apply_patch {input: string}` |
| `Reasoning` | `reasoning` item with `encrypted_content` | dropped | `thinking` block with signature |

Compatibility switch `tool_results_as_user_messages`: some local
OpenAI-compatible servers reject the `tool` role (the existing Brave flow works
around this by injecting results as a user message). When set, tool outputs
are serialized as user messages prefixed with the call id and tool name, and
calls as assistant text. Such providers are marked `degraded_tools` in the
model picker.

### 4.3 Stream events

```rust
enum ResponseEvent {
    Created,
    OutputItemAdded(ResponseItem),
    OutputItemDone(ResponseItem),
    OutputTextDelta { item_id: String, delta: String },
    ReasoningSummaryDelta { item_id: String, summary_index: u32, delta: String },
    ReasoningContentDelta { item_id: String, content_index: u32, delta: String },
    ToolCallInputDelta { item_id: String, call_id: CallId, delta: String },
    RateLimits(RateLimitSnapshot),
    Completed { response_id: Option<String>, usage: TokenUsage, end_turn: Option<bool> },
}

struct TokenUsage { input: u64, cached_input: u64, cache_write_input: u64, output: u64, reasoning_output: u64 }
```

Chat Completions and Anthropic streams are reassembled into whole items before
`OutputItemDone` (tool-call argument fragments are concatenated per index).

### 4.4 Prompt caching

- `prompt_cache_key = thread_id` on Responses.
- Anthropic: `cache_control` on the last system block, the last tool spec, and
  the last history item before the newest user input.
- History is append-only between compactions, so prefixes stay stable. Tool
  list order is deterministic (sorted by registration order, then name).

## 5. History

### 5.1 ContextManager

Per-thread in-memory model history rebuilt from the log on load:

```rust
struct ContextManager {
    items: Vec<(Ordinal, ResponseItem)>,
    token_info: TokenUsageInfo,      // last reported usage + byte-based estimate since
    reference_context: Option<ContextSnapshot>, // environment/instructions last sent
}
```

### 5.2 Normalization (`for_prompt`)

Applied every step, never written back:

1. Every call has an output: a call without output gets a synthetic
   `aborted` output; an output without a call is removed.
2. Images are removed for text-only models and replaced by `[image omitted]`.
3. Reasoning items from a different provider are removed.
4. `Other` items are removed unless the provider declares support.
5. Tool outputs larger than the per-item history cap (default 10,000 tokens,
   Codex default `max_output_tokens`) are truncated head+tail with an omission
   marker; the full output stays in the event log for the UI.

### 5.3 Token accounting

The authoritative count is the provider's reported usage for the last request.
Items added since are estimated at 4 bytes per token (Codex uses a byte-based
lower bound). `compaction_limit = min(config.auto_compact_token_limit,
context_window * 9 / 10)`, matching Codex `auto_compact_token_limit()`.

## 6. Context assembly

### 6.1 Layers, in prompt order

1. **Base instructions** for the model family (§2.3) — the `instructions` field.
2. **Developer message**: approval/sandbox contract, collaboration mode
   (Plan mode instructions when active), available skills catalog (§6.3),
   subagent roster when the thread has children.
3. **User instructions message**: the conversation's system prompt and memory
   (existing chatbot-rust concepts), then the project docs (§6.2) wrapped as
   `<project_instructions path="…">…</project_instructions>`.
4. **Environment context message**: cwd, workspace name, repository, branch,
   sandbox profile, network policy, shell, current date and timezone. Emitted as
   a diff against `reference_context` when it changes mid-thread rather than
   repeated in full.
5. History.

Layers 2–4 are inserted as history items at thread start and re-emitted only
when they change; this keeps the prompt prefix cacheable.

### 6.2 Project docs (`AGENTS.md`)

Codex discovery, reproduced:

- Find the project root: walk up from cwd to the nearest directory containing a
  root marker (default `.git`); if none, use cwd only.
- Collect, from the root down to cwd, at each level the first existing of
  `AGENTS.override.md`, `AGENTS.md`, then configured fallback names
  (default fallbacks: `CLAUDE.md`, so repositories written for Claude Code work).
- Concatenate root-first, each prefixed with its path, capped at
  `project_doc_max_bytes` (default 32 KiB, Codex `DEFAULT_PROJECT_DOC_MAX_BYTES`);
  truncation keeps the deepest (most specific) files whole.
- Untrusted workspaces (§11.3) load no project docs.
- The runner reads the files (`ReadContextFiles`); the control plane caches
  them per turn keyed by content hash.

### 6.3 Skills

- Discovery roots, lowest to highest precedence: built-in skills shipped with
  `chatbot-agent`, user skills (stored encrypted in the control plane),
  repository skills under `.agents/skills/<name>/SKILL.md` from project root to
  cwd.
- `SKILL.md` has YAML frontmatter: `name`, `description`,
  `metadata.short-description`, optional `allow_implicit_invocation`
  (default true).
- Only the catalog (name + short description + path) is in context. The body is
  injected as a user-role item when the user writes `$name`, or when the model
  calls the `load_skill` tool for a skill with implicit invocation allowed.
- Supporting files in the skill directory are readable through normal tools.

### 6.4 Memories

Out of scope for phase 1. The existing per-conversation memory field is injected
as part of layer 3. A later phase may adopt Codex's two-stage
extract/consolidate memory pipeline, stored per user and encrypted.

## 7. Compaction

### 7.1 Triggers

| Phase | Trigger |
|---|---|
| `PreTurn` | tokens ≥ limit before the turn, or model switch to a smaller window |
| `MidTurn` | after a step that needs follow-up when tokens ≥ limit, or on `ContextWindowExceeded` |
| `PostTurn` | optional policy: compact idle threads above 75 % of limit so the next turn starts fast |
| Manual | `Op::Compact` / UI button |

Run `PreCompact` hooks first (§10); they may veto manual compaction only.

### 7.2 Local algorithm

1. Build a summarization prompt: the history plus a fixed `SUMMARIZATION_PROMPT`
   asking for a handoff summary (goal, decisions, files touched, current state,
   open tasks, exact identifiers to keep).
2. Sample with the same model (or `compact_model` if configured and eligible).
3. Replace history with: initial context layers (§6.1, current values), the most
   recent user messages up to a 20,000-token budget (newest first, so the latest
   intent survives verbatim), then a `Compaction { summary }` item.
4. Record `ContextCompacted { phase, reason, tokens_before, tokens_after }`.
   Earlier items stay in the event log; only the model history is replaced
   (Codex `replace_compacted`).

Providers that support server-side compaction (Responses `compact` endpoint)
may use it instead; the result is stored as an opaque `Compaction` item tied to
that provider and falls back to local compaction on provider change.

### 7.3 Failure

If compaction itself exceeds the window, drop the oldest non-initial items one
by one and retry (bounded to 3 attempts), then fail the turn with
`context_window_exceeded`.

## 8. Errors and turn outcomes

```rust
enum TurnStatus { InProgress, Completed, Interrupted, Failed(TurnError), AwaitingKey, AwaitingApproval }

enum TurnError {
    ContextWindowExceeded,
    UsageLimit { resets_at: Option<Timestamp> },
    ProviderUnavailable { attempts: u32 },
    PrivacyDenied { destination: String },
    BudgetExceeded,
    RunnerUnavailable,
    Internal { reference: String },
}
```

A tool failure is not a turn failure: it becomes a tool output the model sees.
A turn fails only on errors that make further sampling impossible.

## 9. Subagents

### 9.1 Semantics

Codex has two collaboration tool generations. Adopt V2 addressing (paths) with
a V1-style tool surface, because paths make the tree legible in the UI and V1's
tool names are the most widely trained.

Tools (registered when `features.subagents` and depth < `max_depth`):

| Tool | Arguments | Result |
|---|---|---|
| `spawn_agent` | `task_name` (slug), `message`, `role?`, `model?`, `reasoning_effort?`, `fork_context: none\|all\|last_n(n)` | `{agent_path, nickname}` |
| `send_input` | `target` (path), `message`, `interrupt?` | ack |
| `wait_agent` | `targets[]`, `timeout_ms?` | per-target status + final message for completed ones |
| `list_agents` | — | children with status |
| `close_agent` | `target` | final status |

Statuses: `pending_init`, `running`, `interrupted`, `completed(message)`,
`errored(error)`, `shutdown`, `not_found`.

### 9.2 Child configuration

Precedence (highest first): operator `agents.default_subagent_model` override >
spawn arguments > role definition > parent's effective config. Children inherit
privacy (cannot loosen), workspace, sandbox policy (may tighten), approval
policy, and the parent's remaining budget share. Approval requests from a child
surface in the root conversation with the child's path.

Limits: `agents.max_threads` (default 6 concurrently running per user),
`agents.max_depth` (default 2).

### 9.3 Roles

Roles are config overlays with `description` and `nickname_candidates`, e.g.
`explorer` (read-only sandbox, cheaper model), `worker` (workspace-write),
`reviewer` (read-only, review prompt). Defined in operator config and
`.agents/roles/*.toml` in trusted repositories.

### 9.4 Storage

Each child is a thread with `parent_thread_id` and `agent_path`. The agent graph
(edges `Open|Closed`) is part of the root thread's state in the log. Child
threads are listed under their root in the UI and are not separate
conversations.

## 10. Hooks

Operator- and repository-configured commands run by the runner (repository hooks
only in trusted workspaces). Input is JSON on stdin; output is JSON on stdout.

| Event | Can |
|---|---|
| `SessionStart` | add context |
| `UserPromptSubmit` | block, add context |
| `PreToolUse` | block with reason, rewrite input |
| `PermissionRequest` | allow/deny (any deny wins; otherwise last allow wins) |
| `PostToolUse` | add context, mark failure |
| `PreCompact` / `PostCompact` | veto manual compaction / observe |
| `SubagentStart` / `SubagentStop` | observe, block stop with reason |
| `Stop` | block stop with a continuation reason (bounded to 3 per turn) |

Hooks have a 60 s default timeout and are events in the log (`HookStarted`,
`HookCompleted`).

## 11. Configuration

### 11.1 Layers

Lowest to highest: built-in defaults < operator config (`config.yml` agent
section) < user settings (encrypted, per user) < trusted repository
`.agents/config.toml` < per-thread settings < per-turn overrides.

Restrictions merge in the tightening direction only from lower-trust layers: a
repository can make the sandbox stricter or remove tools, never grant network
access, raise budgets or lower privacy.

### 11.2 Profiles

- **Permission profiles** (sandbox + approval + network bundles): `read-only`,
  `auto` (workspace-write, on-request approvals, no network), `full-auto`
  (workspace-write, approvals never, network allowlist), `danger` (operator-only).
- **Model profiles**: named model + effort + compaction settings.

### 11.3 Trust

A workspace repository is `Untrusted` until the user marks it trusted. Untrusted
repositories load no project docs, skills, roles, hooks or config, and default
to the `read-only` permission profile.

## 12. Budgets

Per turn and per user per day: token budget per provider, wall-clock limit
(default 2 hours per turn), tool-call count limit (default 500 per turn).
Exceeding a budget ends the turn with `BudgetExceeded` after recording the
current step. Usage is attributed to every attempt, including retries and
compaction.

## 13. Codex features deliberately deferred

Code mode (model-written scripts invoking tools), realtime voice conversations,
plugin marketplaces, connectors/apps, guardian reviewer, ChatGPT-login auth,
tool search, image generation, `request_permissions` mid-turn escalation (use
approvals instead), deferred executors. Each can be added behind `FeatureSet`.
