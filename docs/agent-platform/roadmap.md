# Roadmap

Phases are ordered so each one ships something usable and later phases build
on contracts the earlier ones fixed. Harness adapters come before native coding
tools because they give working coding agents sooner. The native loop exists
from phase 0, so its contracts are exercised early, but it gains workspace tools
only in phase 2.

## Phase 0: Threads without execution

No agent host is needed in this phase.

Scope:

- Provider gateway wire formats: Responses and Messages tool calling, reasoning
  items, usage accounting and prompt caching, with Chat Completions as a
  fallback (agent-loop.md §4, architecture.md §4).
- The `chatbot-agent` crate running in-process (architecture.md §6), with
  `run_turn`, sampling and retry, steering, interrupt, context manager and
  compaction (agent-loop.md §1–§8).
- Tools that need no workspace: `web_search` (Brave), `update_plan`,
  `request_user_input`, and remote MCP servers over streamable HTTP through the
  egress validator.
- Thread/turn/item model, the encrypted event log, replay and the thread HTTP
  API (events-and-storage.md §1–§6). Sets reference threads (§4.6).
- Custody modes Attended and Run key (architecture.md §5.3–§5.4).
- Web UI: thread view, reducer, item cards, request banner, Inbox (ui.md §1–§4,
  §6.1–§6.2).

Exit criteria:

- A thread survives browser reloads and network drops with no duplicated or
  missing items: reducer fixture tests replay gaps, duplicates and `EventsLost`.
- One turn performs several sampling steps with tool calls on each supported
  wire format, verified against recorded provider fixtures.
- A thread's log cannot be read without its owner's key; tests cover a wrong
  AAD, a wrong key, and a truncated segment.
- Privacy eligibility rejects a `private` thread routed to a `non_private`
  provider, both before the first step and on a mid-thread model change.

## Phase 1: Workspaces and harnesses

Scope:

- Workspace manager and per-user runner containers on an agent host
  (architecture.md §1.3–§1.4), and the runner protocol (§3).
- Workspaces, repositories, worktrees, the GitHub App connection, the token
  broker and `GitOp` (workspaces-git.md §1–§4).
- PTY terminals: workspace shell and harness side terminals, xterm.js view
  (harness-adapters.md §7, ui.md §5).
- Harness adapters: Codex app-server, Claude Code stream-json, runner-local
  OpenCode, and the terminal runtime (harness-adapters.md §2–§5, §7), with the
  approvals bridge and the terms of service rules (§8).
- Gateway routing for harnesses in API-key mode (harness-adapters.md §9).
- Workspaces view and runtime picker (ui.md §6).

Exit criteria:

- From a phone, the operator starts a Codex or Claude Code thread on a
  repository, approves a command, sees file changes, and creates a pull request.
- Killing a harness process or the runner mid-turn yields
  `Failed(RunnerUnavailable)`, and the next turn resumes the harness session.
- A runner cannot reach another runner, the control plane's non-runner APIs, or
  any host outside its network policy (tested from inside the container).
- Model-run `git push` fails without credentials; `GitOp` push succeeds with a
  repository-scoped token. Both cases are tested.
- No subscription login leaves the owning user's harness home (tested by
  checking the control plane never requests harness-home paths).

## Phase 2: Native coding agent and restart durability

Scope:

- Native workspace tools: `exec_command`/`write_stdin`, `apply_patch`, file
  tools, `view_image`, `git_push`, `create_pull_request` (tools.md §3–§5).
- Inner sandbox with bwrap, seccomp and the egress proxy; exec policy; the
  full approval decision table and amendments (tools.md §6–§8).
- Turn snapshots, undo, fork and turn diff (workspaces-git.md §5).
- AGENTS.md chain, skills and trusted repository config (agent-loop.md §6, §11).
- Restart durability: the control plane rebuilds thread actors from the log,
  marks interrupted turns, and resumes runs whose custody allows it; runners
  reconnect and report live processes (architecture.md §3.4, §7).
- Review mode (agent-loop.md §1, `SessionTask::Review`).

Exit criteria:

- The native agent completes a fixed task set (a failing test to fix, a
  feature with tests, a refactor across files) in a pinned fixture repository,
  with results comparable to Codex using the same model.
- `apply_patch` grammar and `seek_sequence` tests match Codex fixtures.
- A sandbox escape test suite (writes outside writable roots, network without
  approval, reads of the helper socket) fails closed.
- Restarting the control plane during a Run-key turn resumes it with no lost
  or duplicated events; an Attended turn moves to `awaiting_key`.

## Phase 3: Chat on threads and mobile

Scope:

- Plain chat becomes a native thread without workspace tools; the RAM-only
  generation registry and the special Brave flow are retired; existing sets
  stay readable as pairs (events-and-storage.md §2.2, §4.6; tools.md §3.7).
- Android push for approvals and questions, and Android Auto thread mode with
  voice approvals (ui.md §7.2–§7.3).
- Remote OpenCode connections gain sessions and events (harness-adapters.md §5.1).

Exit criteria:

- Every existing chat test passes against the thread-backed chat path, and old
  sets render unchanged.
- An approval requested while the phone is locked is delivered by push, decided
  on the phone, and the turn continues; the push payload contains no content.
- Voice approval in the car works for exec approvals and refuses patches over
  20 lines.

## Phase 4: Breadth

Scope:

- Native subagents (agent-loop.md §9) with child threads in the UI (ui.md §6.3).
- Hooks (agent-loop.md §10) and per-user config layers and profiles (§11).
- ACP adapters for Gemini CLI and Hermes (harness-adapters.md §6).
- Server-managed custody (architecture.md §5.3) for users who opt in.
- Memories, exposing workspace tools as an MCP server, and SSH remotes
  (agent-loop.md §6.4, tools.md §9.3, workspaces-git.md §4.5).

Exit criteria are set per feature when the phase starts.

## Open decisions

| Decision | Options | Current lean | Decide by |
|---|---|---|---|
| Runner isolation | Containers on a dedicated agent host; per-user microVMs (Firecracker, Kata); gVisor runtime | Containers on a dedicated host while only the operator and trusted users run agents; microVMs before untrusted users get workspaces | Phase 1 start |
| Native loop placement | In-process; runner-hosted (architecture.md §6) | In-process | Phase 0 start |
| Custody defaults | Attended for `private` and Run key for `standard` (architecture.md §5.3), or Run key everywhere with a warning | As specified | Phase 0 exit |
| Event log store | Separate redb file per deployment (events-and-storage.md §4); tables in the existing history store | Separate redb | Phase 0 start |
| GitHub identity default | GitHub App; OAuth user token | App for repository access, OAuth only for user-authored PRs | Phase 1 start |
| Push provider | FCM; UnifiedPush; none (polling while the app runs) | FCM with content-free payloads | Phase 3 start |
| Claude subscription mode | Enabled for the operator only; disabled | Operator only, after checking Anthropic's current terms | Phase 1 start |
| Harness version policy | Pinned per runner image; user-upgradable inside the runner | Pinned, with a probe that disables adapters on unknown versions | Phase 1 start |
