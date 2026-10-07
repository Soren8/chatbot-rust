# Events and Storage

The thread/turn/item data model, the event envelope shared by the native loop
and every harness adapter, the encrypted append-only event log, replay, and the
HTTP API. This replaces the RAM-only durable-generation registry for agent
threads and, from roadmap phase 3, for chat as well.

The model follows Codex app-server v2 (`ThreadItem`, `item/started` →
deltas → `item/completed`, turn status) and Codex rollouts (append-only records
with ordinals, separate model history and UI events). It is not wire-compatible
with either.

## 1. Data model

### 1.1 Identifiers

| Id | Format | Scope |
|---|---|---|
| `thread_id` | UUIDv7 | global; owner-scoped in routes |
| `turn_id` | UUIDv7 | within a thread |
| `item_id` | `<turn-ordinal>-<n>` (e.g. `t12-4`), or the provider item id when stable | within a thread |
| `seq` | u64, strictly increasing, gap-free | within a thread's event log |
| `request_id` | UUIDv7 | approvals, user-input requests, client tool calls |

UUIDv7 keeps ids time-ordered for index scans. `seq` is the only ordering
clients rely on.

### 1.2 Thread

```rust
struct Thread {
    id: ThreadId,
    owner: UserId,
    conversation_id: Option<SetId>,       // the saved set it belongs to; None for workspace-only threads
    parent: Option<ParentRef>,            // { thread_id, agent_path, spawned_by_item } for subagents
    runtime: RuntimeKind,                 // native | opencode | codex | claude | acp | terminal
    privacy: PrivacyLevel,
    custody: CustodyMode,                 // architecture.md §5.3
    workspace: Option<WorkspaceBinding>,  // { workspace_id, worktree_id, cwd }
    settings: ThreadSettings,             // model, effort, approval policy, permission profile, collaboration mode
    status: ThreadStatus,                 // idle | running | awaiting_approval | awaiting_input | awaiting_key | failed | archived
    title: Option<String>,
    created_at: Timestamp,
    updated_at: Timestamp,
    head_seq: u64,
    version: u64,                         // CAS for metadata mutations
}
```

Thread metadata (except title, which is content) is stored in plaintext index
records so lists can be rendered without a key; the title is sealed like
content.

### 1.3 Turn

```rust
struct Turn {
    id: TurnId,
    ordinal: u32,
    status: TurnStatus,                   // agent-loop.md §8
    started_at: Timestamp,
    completed_at: Option<Timestamp>,
    usage: TokenUsage,
    settings_summary: TurnSettingsSummary,
    first_seq: u64,
    last_seq: Option<u64>,
}
```

### 1.4 Items

```rust
enum ThreadItem {
    UserMessage { id, content: Vec<UserInput>, kind: UserMessageKind /* initial | steer | queued | inter_agent */ },
    AgentMessage { id, text: String, phase: Option<MessagePhase> /* commentary | final */ },
    Reasoning { id, summary: Vec<String>, content: Option<Vec<String>> },
    Plan { id, explanation: Option<String>, steps: Vec<PlanStep> },
    CommandExecution {
        id, command: String, cwd: String, source: CommandSource /* agent | user | hook */,
        session_id: Option<u32>, tty: bool, status: ItemStatus,
        output: OutputRef,                // inline up to 64 KiB, else chunked blob
        exit_code: Option<i32>, duration_ms: Option<u64>,
        sandbox: SandboxSummary,
    },
    FileChange { id, changes: Vec<FileChangeEntry>, status: ItemStatus },
    McpToolCall { id, server: String, tool: String, arguments: Value, status, result: Option<Value>, error: Option<String>, duration_ms: Option<u64> },
    ToolCall { id, tool: String, namespace: Option<String>, arguments: Value, status, output: Option<ToolOutputPayload>, duration_ms: Option<u64> },  // builtin non-exec tools, dynamic client tools
    WebSearch { id, query: String, results: Vec<SearchResultSummary>, status },
    ImageView { id, path: String },
    Approval { id, request: ApprovalRequest, decision: Option<ReviewDecision>, decided_by: Option<UserId>, decided_at: Option<Timestamp> },
    UserInputRequest { id, questions: Vec<Question>, answers: Option<Vec<Answer>> },
    SubagentCall { id, tool: CollabTool, target_paths: Vec<AgentPath>, prompt: Option<String>, states: Vec<AgentStateSummary>, status },
    ContextCompaction { id, phase: CompactionPhase, tokens_before: u64, tokens_after: u64 },
    Review { id, entered: bool, review: Option<ReviewOutput> },
    Hook { id, event: HookEvent, status, output: Option<String> },
    TerminalSession { id, session_id: TerminalId, title: String, status },  // harness PTY (harness-adapters.md §7)
    Notice { id, level: NoticeLevel, text: String },    // warnings, harness-specific info, events_lost
    Unknown { id, kind: String, payload: Value },       // adapters forward items they cannot map
}

enum ItemStatus { InProgress, Completed, Failed, Declined, Interrupted }
```

The completed item is authoritative. Deltas are for live rendering; a client
that missed deltas but has `ItemCompleted` has the full state.

### 1.5 Model history is separate

The native loop's model history (`ResponseItem`s, agent-loop.md §4.1) is
recorded in the same log as `HistoryAppend` / `HistoryReplace` records. UI
items are not reconstructed from model history or vice versa. Harness adapters
do not produce model history; their harness owns it.

## 2. Event envelope

```rust
struct ThreadEvent {
    seq: u64,
    thread_id: ThreadId,
    turn_id: Option<TurnId>,
    ts: Timestamp,
    origin: EventOrigin,       // native | adapter:<kind> | control
    body: EventBody,
}

#[serde(tag = "type", rename_all = "snake_case")]
enum EventBody {
    // Thread
    ThreadStarted { thread: ThreadSummary },
    ThreadSettingsChanged { settings: ThreadSettings },
    ThreadStatusChanged { status: ThreadStatus },
    // Turn
    TurnStarted { turn: TurnSummary },
    TurnCompleted { turn: TurnSummary },       // status inside: completed | interrupted | failed
    TurnDiff { unified_diff: String, exact: bool },
    TokenCount { last: TokenUsage, total: TokenUsage, context_window: Option<u64> },
    RateLimits { snapshot: RateLimitSnapshot },
    // Items
    ItemStarted { item: ThreadItem },
    ItemUpdated { item: ThreadItem },          // whole-item replacement (plan, subagent states)
    ItemCompleted { item: ThreadItem },
    AgentMessageDelta { item_id: ItemId, delta: String },
    ReasoningDelta { item_id: ItemId, summary_index: u32, delta: String },
    CommandOutputDelta { item_id: ItemId, stream: OutputStream, chunk: Base64Bytes },
    ToolInputDelta { item_id: ItemId, delta: String },   // apply_patch preview
    // Requests to the user
    ApprovalRequested { request: ApprovalRequest },
    ApprovalResolved { request_id: RequestId, decision: ReviewDecision },
    UserInputRequested { request_id: RequestId, questions: Vec<Question> },
    UserInputAnswered { request_id: RequestId },
    ClientToolCall { request_id: RequestId, tool: String, arguments: Value },
    // Diagnostics
    StreamError { message: String, retrying_in_ms: Option<u64>, attempt: u32 },
    Warning { message: String },
    Error { error: TurnError },
    // Storage
    HistoryAppend { items: Vec<ResponseItem> },              // not sent to clients
    HistoryReplace { items: Vec<ResponseItem>, reason: ReplaceReason },  // compaction; not sent to clients
    EventsLost { from_seq: u64, to_seq: u64 },              // architecture.md §5.4
    Heartbeat,                                               // transport only; not persisted
}
```

`HistoryAppend`/`HistoryReplace` are persisted but filtered from client
streams. `Heartbeat` is transport-only. Every other event is persisted, then
broadcast.

### 2.1 Deltas and coalescing

To bound log volume, deltas are coalesced before persistence: text deltas per
item are merged until 250 ms or 4 KiB, command output until 250 ms or 16 KiB.
Live subscribers receive the coalesced event; there is no unpersisted fast
path, so a reconnecting client sees exactly what a live client saw.

Once an item completes, its delta events become redundant. Log compaction
(§4.5) may drop them for finished turns.

### 2.2 Relation to the existing durable generation events

Existing `{generation_id, seq, type, channel, text}` events map as:
`channel: answer` → `AgentMessageDelta`, `channel: thinking` →
`ReasoningDelta`, terminal events → `TurnCompleted`. During the transition,
`activity-sync.js` keeps consuming the old stream for chat while new thread
views consume `ThreadEvent`s (ui.md §2).

## 3. Thread actor and broadcast

Each loaded thread has one actor (architecture.md §7) that owns:

- the next `seq`;
- an append pipeline: seal → write → fsync policy → broadcast;
- a `tokio::sync::broadcast` channel to live subscribers with a bounded buffer
  (1,024 events). A subscriber that lags is dropped and must resume from its
  last `seq` via replay; it never silently misses events.

Adapters and the native loop call `EventSink::emit(body)`; they never assign
`seq` themselves.

## 4. Encrypted event log

### 4.1 Storage layout (redb, `chatbot-core/src/agent_log/`)

| Table | Key | Value |
|---|---|---|
| `threads` | `(owner, thread_id)` | plaintext `ThreadIndex` (ids, status, runtime, timestamps, `head_seq`, `version`, privacy, custody) |
| `thread_keys` | `(owner, thread_id, key_epoch)` | wrapped run key: `{wrap: data_key \| server_master, nonce, ciphertext}` |
| `events` | `(thread_id, seq)` | sealed `ThreadEvent` record |
| `segments` | `(thread_id, segment_no)` | sealed snapshot: rebuilt thread state as of a seq (§4.4) |
| `turns` | `(thread_id, turn_ordinal)` | plaintext `{turn_id, first_seq, last_seq, status}` for seeking |
| `blobs` | `(thread_id, blob_id)` | sealed large payloads (command output > 64 KiB, images) in 256 KiB chunks |
| `pending_requests` | `(owner, request_id)` | plaintext pointer `{thread_id, kind, created_at}` to list approvals without a key |

The plaintext index reveals timing, sizes, status and runtime kind, not content;
this matches what the existing history store reveals about sets.

### 4.2 Keys

- Each thread has a run key per `key_epoch`. Epoch 0 is created with the
  thread. Rotation (after custody-mode change or on request) starts a new
  epoch; older records keep their epoch.
- Subkeys: `HKDF-SHA256(run_key, salt = thread_id, info = "agent-log/v1/" + purpose)`
  with purposes `events`, `blobs`, `segments`.
- Wrapping: `AES-256-GCM(kek, run_key)` where `kek = HKDF(data_key, info =
  "agent-log/wrap/v1")` for `Attended`/`RunKey`, or the server master key for
  `ServerManaged`.

### 4.3 Sealed append

```text
seal(event):
    plaintext = canonical CBOR(event without seq/thread_id)
    aad = "agent-log/v1" || owner || thread_id || seq (u64 BE) || key_epoch || record_kind
    nonce = 96 random bits
    ciphertext = AES-256-GCM(subkey_events, nonce, plaintext, aad)
    record = { v: 1, key_epoch, nonce, ciphertext }
append(event):
    write record at (thread_id, seq) in a redb write transaction
    update threads.head_seq (same transaction)
    commit; then broadcast
```

AAD binds owner, thread and position, so records cannot be moved between
threads or reordered. A missing `seq` on read is corruption, except within a
recorded `EventsLost` range.

Durability: `redb` commits with `Durability::Immediate` for lifecycle events
(turn started/completed, approvals, item completed) and `Durability::Eventual`
for deltas, with a forced immediate commit at least every second while a turn
is active. A crash can lose at most the last second of deltas, never a
completed item.

Throughput target: 2,000 appends per second per process on the agent host with
batching of concurrent appends into one transaction.

### 4.4 Snapshots

Every 2,000 events, and at turn completion if more than 500 events since the
last snapshot, the actor writes a sealed `segment`: current thread state
(items of open turns, model history, pending requests, agent graph, session
approval cache). Loading a thread = latest segment + replay of later events.

### 4.5 Retention and log compaction

- Delta events of completed turns older than 7 days are deleted after their
  turn's items are confirmed complete (a background job, key-free: it deletes
  by `seq` ranges recorded in plaintext `turns` metadata and a plaintext
  per-event `kind` byte stored beside the record).
- Deleting a thread deletes all its tables' rows and its wrapped keys
  (crypto-shredding: wrapped keys are removed first).
- Deleting a conversation deletes its threads.

### 4.6 Relation to the history store

Saved sets keep their existing format. A set gains an optional list of thread
references `{thread_id, after_pair_index}` so agent threads appear inline in the
conversation. Adding a reference is a normal CAS mutation on the set. Plain chat
remains pairs until roadmap phase 3 moves chat onto threads.

## 5. Replay and live streaming

### 5.1 Subscription

```
GET /threads/{id}/events?after_seq=N[&include=deltas|items_only][&wait=1]
Accept: application/x-ndjson
```

1. Authenticate; check owner; acquire the key per custody mode (a request
   without a key to an encrypted thread returns `423 key_required`).
2. Stream records `after_seq` from the log in order. If the client is far
   behind (more than 5,000 events) and `include=items_only`, the server sends
   a `ThreadSnapshot` built from the latest segment instead, then events after
   it.
3. Switch to the live broadcast without a gap: subscribe to broadcast first,
   note the head, replay to the head, then forward live events skipping
   `seq ≤ head`.
4. Heartbeat every 5 s (existing durable generation behavior; the client's 20 s
   silence timeout stays).

Clients persist `last_seq` and resume with it. Duplicate `seq` values are
ignored by the client reducer (ui.md §2).

### 5.2 Disconnect semantics

Unchanged from durable generations: a dropped connection never cancels work or
duplicates a turn. Only explicit `interrupt` stops a turn.

### 5.3 Multiple viewers

Any number of the owner's devices may subscribe. Approvals are first-writer-wins
per request id; the losing device receives `ApprovalResolved` and closes its
prompt.

## 6. HTTP API

All routes are owner-scoped, require CSRF for mutations (existing
`session-client.js` flow), accept `Idempotency-Key` on every POST that creates
work, and use the existing idempotency receipt store.

### 6.1 Threads

| Method | Route | Body / query | Result |
|---|---|---|---|
| POST | `/threads` | `{runtime, conversation_id?, workspace?: {workspace_id, worktree?, cwd?}, settings?, title?}` | `201 Thread` |
| GET | `/threads` | `?conversation_id&status&runtime&cursor&limit` | page of `ThreadIndex` |
| GET | `/threads/{id}` | — | `Thread` + open turn summary + pending requests |
| PATCH | `/threads/{id}` | `{expected_version, settings?, title?, archived?}` | `Thread` |
| DELETE | `/threads/{id}` | `?expected_version` | `204` |
| POST | `/threads/{id}/fork` | `{at_turn: TurnId}` | `201 Thread` (copies model history up to that turn; workspace forked per workspaces-git.md §5.3) |
| GET | `/threads/{id}/items` | `?turn_id&cursor&limit` | page of completed items (built from segments + log) |
| GET | `/threads/{id}/events` | §5.1 | NDJSON |
| GET | `/threads/{id}/blobs/{blob_id}` | `Range` supported | decrypted bytes |

### 6.2 Turns

| Method | Route | Body | Result |
|---|---|---|---|
| POST | `/threads/{id}/turns` | `{input: [UserInput], mode: start_or_queue \| start_or_steer, settings?}` | `202 {turn_id, queued: bool}` |
| POST | `/threads/{id}/turns/{turn_id}/steer` | `{input, preempt?: bool}` | `202` |
| POST | `/threads/{id}/turns/{turn_id}/interrupt` | `{if_no_pending_input?: bool}` | `202` |
| POST | `/threads/{id}/compact` | — | `202` |
| POST | `/threads/{id}/review` | `{target: uncommitted \| base_branch{branch} \| commit{sha} \| custom{instructions}}` | `202 {turn_id}` |
| POST | `/threads/{id}/shell` | `{command, timeout_ms?}` | `202 {item_id}` |

`UserInput`:

```json
{"type": "text", "text": "..."}
{"type": "image", "upload_id": "..."}
{"type": "file_mention", "path": "src/main.rs", "range": [10, 40]}
{"type": "skill", "name": "release-notes"}
```

### 6.3 Requests

| Method | Route | Body |
|---|---|---|
| GET | `/requests` | pending approvals/questions across all threads (from plaintext pointers; payload decrypted when the key is present) |
| POST | `/threads/{id}/approvals/{request_id}` | `{decision: approved \| approved_for_session \| approved_amendment{prefix} \| network_amendment{host, scope} \| denied{reason?} \| abort}` |
| POST | `/threads/{id}/user_input/{request_id}` | `{answers: [{id, selected: [label], text?}]}` |
| POST | `/threads/{id}/client_tool_results/{request_id}` | `{output: string \| content_items, success}` |

Errors: `409 approval_stale` (agent-loop/tools.md §6.3), `409 already_resolved`,
`410 request_expired`.

### 6.4 Terminals

Harness and user terminals (harness-adapters.md §7):

| Method | Route | Notes |
|---|---|---|
| GET (WebSocket) | `/threads/{id}/terminals/{terminal_id}` | same-origin, CSRF token in the first frame; binary frames = PTY bytes, text frames = `{resize: [cols, rows]}` |
| POST | `/threads/{id}/terminals/{terminal_id}/kill` | |

This is the only WebSocket route. It is needed for interactive latency; event
streams stay NDJSON over HTTP so they keep working through the existing proxy
and Android WebView setup.

### 6.5 Errors

Error bodies keep the existing `{error: code, message}` shape. New codes:
`key_required` (423), `thread_busy` (409, a turn is running and mode does not
allow queueing), `runtime_unavailable` (503), `workspace_unavailable` (503),
`privacy_denied` (403), `budget_exceeded` (429).

## 7. Import/export

- Export: `GET /threads/{id}/export?format=jsonl` streams decrypted events
  (minus `HistoryAppend`/`HistoryReplace` unless `include_history=1`) for
  backup and debugging.
- Import of Codex rollouts (`~/.codex/sessions/**/*.jsonl`) and Claude Code
  transcripts is a later convenience; the mapping is the same as the adapters'
  (harness-adapters.md §3.3, §4.3).
