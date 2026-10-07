# User Interface

How threads, items, approvals, workspaces and terminals are presented on the
web UI, the Android app (Capacitor WebView) and Android Auto.

The UI is one application for chat and agents. A conversation shows plain chat
pairs and agent threads in the same timeline; the runtime decides which
controls are shown, not which page the user is on.

## 1. Structure

### 1.1 Layout

```
┌──────────────┬───────────────────────────────────────────┬──────────────────┐
│ Sidebar      │ Thread view                               │ Context panel    │
│              │                                           │ (collapsible)    │
│ Conversations│  header: title · runtime · model ·        │                  │
│  └ threads   │          privacy · workspace/branch       │ Plan             │
│ Inbox (n)    │  ─────────────────────────────────────    │ Turn diff        │
│ Workspaces   │  turns → item cards                       │ Subagents        │
│ Connections  │  pending request banner                   │ Terminals        │
│              │  ─────────────────────────────────────    │ Usage / limits   │
│              │  composer: input · mode · model · send/   │                  │
│              │            steer/stop                     │                  │
└──────────────┴───────────────────────────────────────────┴──────────────────┘
```

- Below 900 px the context panel becomes a bottom sheet with tabs; below
  600 px the sidebar is a drawer (current behavior).
- The **Inbox** lists pending approvals and questions across all threads
  (`GET /requests`), newest first, with the thread title and runtime.

### 1.2 Modules

New UMD modules follow the existing pattern (explicit dependencies, safe DOM
builders, no framework, Node fixture tests):

| Module | Role |
|---|---|
| `thread-sync.js` | Subscribe/replay/resume for `/threads/{id}/events`; reuses `activity-sync.js` backoff and silence timeout |
| `thread-state.js` | Pure reducer: events → thread view model (§2) |
| `thread-renderer.js` | Item cards from the view model; keyed DOM updates |
| `approvals.js` | Request banner, inbox, decision posting |
| `diff-view.js` | Unified diff parsing and rendering (§4) |
| `terminal-view.js` | xterm.js wrapper over the terminal WebSocket (§5) |
| `workspace-view.js` | Workspaces, repositories, worktrees, GitHub connections |

xterm.js is the only new third-party browser dependency; it is vendored under
`static/vendor/` and pinned.

## 2. Event reducer

`thread-state.js` is a pure function `reduce(state, event) → state` with no DOM
access, so it is tested with Node fixtures like the existing modules.

```text
state = {
  thread, last_seq,
  turns: OrderedMap<TurnId, {summary, item_ids: [ItemId]}>,
  items: Map<ItemId, ItemView>,
  pending: Map<RequestId, Request>,
  diff, usage, rate_limits, status, lost_ranges: [],
}

reduce(state, ev):
  if ev.seq <= state.last_seq: return state          // duplicate after reconnect
  if ev.seq != state.last_seq + 1 and state.last_seq != 0:
      mark gap; thread-sync re-subscribes with after_seq = last_seq; return state
  apply by type:
    ThreadStarted / ThreadSettingsChanged / ThreadStatusChanged → thread, status
    TurnStarted       → add turn
    TurnCompleted     → replace turn summary; clear in-progress flags on its items
    ItemStarted       → insert item (status in_progress), append to turn
    ItemUpdated       → replace item
    ItemCompleted     → replace item (authoritative), drop delta buffers
    *Delta            → append to the item's live buffer (create a placeholder if
                        ItemStarted was compacted away)
    ApprovalRequested / UserInputRequested / ClientToolCall → pending.add
    ApprovalResolved / UserInputAnswered → pending.remove
    TurnDiff          → diff
    TokenCount / RateLimits → usage
    EventsLost        → lost_ranges.push; render a notice at that position
    StreamError       → transient banner with retry countdown
  state.last_seq = ev.seq
```

- `last_seq` is kept per thread in `sessionStorage` so a reload resumes with
  `after_seq` instead of replaying the whole thread.
- Opening a long thread uses `GET /threads/{id}/items` for completed turns and
  subscribes from the returned head; the reducer accepts a snapshot as its
  initial state.
- Rendering is batched with `requestAnimationFrame`; deltas mutate the text
  node of their item, never rebuild the card.
- During the transition, chat turns still use `activity-sync.js` and the
  existing renderer. Both modules coexist; a conversation timeline merges chat
  pairs and thread entries by creation time.

## 3. Item cards

Every item kind has a card. Cards are collapsed by default except agent
messages, pending requests and failed items.

| Item | Collapsed | Expanded |
|---|---|---|
| `UserMessage` | text, attachments; steer/queued badge | — |
| `AgentMessage` | Markdown (existing safe renderer); commentary phase shown dimmer | — |
| `Reasoning` | "Thought for 12 s" + first summary line | summaries; raw content only when the setting allows |
| `CommandExecution` | `$ command` · exit code · duration · sandbox badge | output in a monospace block (ANSI colors via a small SGR parser; no HTML), "load full output" for blob-backed output |
| `FileChange` | file list with `+n −m` | per-file diff (§4) |
| `Plan` | progress `3/7` and current step | checklist with statuses |
| `McpToolCall`, `ToolCall` | `server.tool` · status · duration | arguments and result as formatted JSON / text |
| `WebSearch` | query · result count | result titles and links |
| `ImageView` | thumbnail | full image (blob route) |
| `Approval` | decision and who decided | original request |
| `UserInputRequest` | answered summary | questions and answers |
| `SubagentCall` | agent names and states | links to child threads (§6.3) |
| `ContextCompaction` | "Context compacted: 180k → 22k tokens" | — |
| `Review` | findings count | findings with file/line links into the diff view |
| `Hook` | hook event and status | output |
| `TerminalSession` | title · status · "open" | embedded terminal (§5) |
| `Notice` | level icon and text | — |
| `Unknown` | adapter kind | raw JSON |

A turn header shows its status, duration, token usage and a menu: copy,
fork from here, undo (when a snapshot exists), view turn diff.

## 4. Approvals, questions and diffs

### 4.1 Pending request banner

A pending request pins a banner above the composer of its thread and adds an
Inbox badge. The banner renders the request kind:

- **Exec**: command, cwd, the model's justification, sandbox escalation
  requested, and the prefix the amendment option would add. Buttons: Approve,
  Approve for session, Always allow `<prefix>`, Deny, Deny and stop.
- **Patch**: file list and a compact diff preview; Approve, Approve for
  session, Deny.
- **Network**: host and scope; Allow once, Allow host for session, Deny.
- **User input**: the questions with options; free text when `is_other`.
- **Harness-reduced choices**: only the options the harness supports
  (harness-adapters.md §2.5), with the reduction explained.

Decisions are posted with an `Idempotency-Key`. `409 approval_stale` or
`409 already_resolved` closes the banner and shows the actual decision.
Keyboard: `y` approve, `a` approve for session, `n` deny, `Esc` focus composer.

### 4.2 Diff viewer

- Unified view by default, split view at ≥ 1200 px.
- File tree with per-file stats, collapsed binary and large files (> 2,000
  lines changed) behind "show".
- Syntax highlighting is out of scope for phase 1; diffs are colored by line
  type only.
- Sources: `FileChange` items (per change), `TurnDiff` (whole turn), and the
  workspace view's "changes on branch" (`git diff base...HEAD`).
- Actions on a turn diff: undo turn (workspaces-git.md §5.2, with the
  confirmed path list), push branch, create pull request.

## 5. Terminals

- `terminal-view.js` wraps xterm.js with the fit and web-links addons.
- Connection: the terminal WebSocket (events-and-storage.md §6.4). Binary
  frames go straight to `term.write(Uint8Array)`; input from `term.onData` is
  UTF-8 encoded and sent as binary; resize is sent on fit, debounced 100 ms.
- On attach the scrollback ring arrives first; the view shows "reattached" when
  the ring was truncated.
- Input lease: typing takes the lease; other viewers see "controlled by
  <device>" and a "take control" button.
- Mobile: an accessory key row (Esc, Tab, Ctrl, arrows, `|`, `~`) above the
  keyboard.
- Harness login flows (`codex login --device-auth`, `claude /login`) open in a
  terminal from the runtime picker with a short explanation of where the login
  is stored (the user's harness home in their runner).

## 6. Threads, workspaces and runtimes

### 6.1 Starting a thread

The composer's "new" control offers:

- **Chat** (existing behavior until roadmap phase 3).
- **Agent**: runtime picker (native and each probed harness with capability
  icons, privacy level, account label), model and reasoning effort, workspace
  and repository, worktree (`new` default, `main`, or existing), approval
  preset (`Read only`, `Auto` = on-request + workspace-write, `Full access`
  with a confirmation).

Presets map to `ThreadSettings` (agent-loop.md §11); the expanded settings
show the underlying approval policy, sandbox and network values.

### 6.2 Composer

- Enter sends; while a turn runs Enter steers (`start_or_steer`) and
  Alt+Enter queues (`start_or_queue`); a Stop button interrupts.
- `@` opens a file picker backed by the workspace file index (fuzzy search
  over `git ls-files` + untracked, from the runner); selected files become
  `file_mention` inputs.
- `$` opens the skill picker; `/` opens commands (`/compact`, `/review`,
  `/undo`, `/fork`, `/model`, `/shell <cmd>`).
- Images by paste, drop or the attach button (existing upload flow).

### 6.3 Subagents

Native subagents are child threads. The context panel shows the agent tree
(`agent-loop.md` §9) with status per node; selecting a node opens the child
thread read-only in the main view with a breadcrumb back to the parent.
Harness subagents (Claude `Task`, Codex collab) are shown inline in the parent
as nested item groups.

### 6.4 Workspaces view

- Workspace list with status, disk usage and running threads; start/stop.
- Per repository: branches and worktrees, with the thread holding each
  worktree, ahead/behind, dirty state, "open shell" (workspace terminal),
  "changes on branch" (diff view), push, create PR.
- GitHub connections: install app / connect account / add token; list of
  accessible repositories; clone into a workspace.

### 6.5 Status and usage

- Header badges: runtime, model, privacy level (existing colors), workspace
  and branch, and a live status dot (idle, running, waiting for approval,
  awaiting key, failed).
- Context panel usage: tokens of the last step against the context window,
  thread total, estimated cost when known, provider rate limits when reported.

## 7. Notifications

### 7.1 Web

When the thread is not visible: document title badge and, with permission,
a browser Notification for approval requests, user questions and turn
completion of runs longer than 30 s.

### 7.2 Android push

- Capacitor push notifications through FCM, registered per device
  (`POST /devices {platform, token}`), sealed per user.
- Payloads contain no content: `{kind: approval|question|done|failed,
  thread_id, request_id?}`. The app fetches details after unlock with the
  normal session, so privacy levels and encryption are unaffected by the push
  provider.
- Notification actions "Approve" and "Deny" are offered for exec and patch
  approvals only when the user enabled them; they open the app's approval
  screen pre-filled rather than deciding blind, unless the request's command
  matches a prefix the user marked as quick-approvable.

### 7.3 Android Auto

The car surface stays voice-first and respects `CarVoicePolicy`:

- `DurableVoiceProtocol` gains a thread mode: `eventsPath` becomes
  `/threads/{id}/events?after_seq=<seq>`, `apply` consumes `ThreadEvent`s, and
  only `AgentMessage` final-phase text and request summaries are spoken.
- Starting agent work from the car is limited to existing threads with an
  approval preset other than `Full access` ("continue the release thread:
  …").
- Pending requests are read as a one-sentence summary ("Codex wants to run
  cargo test in chatbot-rust"). Voice answers: "approve", "deny", "approve for
  session". Amendments, patches over 20 lines and network approvals are
  deferred to the phone ("I'll leave that for the phone").
- Diffs, command output and terminals are never shown or read in the car.

## 8. Accessibility and testing

- Cards are `article` elements with headings; live regions announce turn
  completion and new requests, not deltas.
- All interactive controls have keyboard paths; focus moves to the request
  banner when a request appears in the visible thread.
- Reducer, diff parser and approval flows get Node fixture tests run from Rust
  (existing pattern). Visual checks use the executor preview flow with
  Playwright screenshots of seeded threads.
