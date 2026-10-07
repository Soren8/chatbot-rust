# Agent Platform Specification

Target design for turning `chatbot-rust` from a chat application into the
primary interface to every AI system the operator uses: chat models, a native
coding agent, and wrapped third-party agent harnesses.

This is a design specification, not a description of deployed behavior.
`docs/design.md`, `docs/design-history-store.md`, `docs/design-privacy.md` and
`docs/durable-activity-design.md` remain authoritative for what exists today.
Where this specification changes an existing contract it says so explicitly.

## Documents

| File | Contents |
|---|---|
| [current-state.md](current-state.md) | What `chatbot-rust` has today, and the gap to an agent platform |
| [architecture.md](architecture.md) | Services, trust boundaries, deployment, privacy and key custody |
| [agent-loop.md](agent-loop.md) | Native agent runtime modeled on Codex: sessions, turns, sampling, steering, context, compaction, subagents, hooks, config |
| [tools.md](tools.md) | Tool registry, built-in tool contracts, exec/PTY, `apply_patch`, approvals, sandboxing, exec policy, MCP |
| [events-and-storage.md](events-and-storage.md) | Thread/turn/item model, event envelope, encrypted event log, replay, HTTP API |
| [workspaces-git.md](workspaces-git.md) | Workspace service, repositories, worktrees, GitHub connections and credentials |
| [harness-adapters.md](harness-adapters.md) | Wrapping OpenCode, Codex, Claude Code, ACP agents and raw terminals |
| [ui.md](ui.md) | Web, Android and Android Auto presentation of runs |
| [roadmap.md](roadmap.md) | Phases, exit criteria and open decisions |

## Goals

1. **One interface.** Chat, coding agents, and wrapped harnesses share one
   conversation list, one event model, one approval surface, and one voice path.
2. **Vertical integration.** The long-term agent loop, tools, context assembly,
   transcript storage and policy are owned by `chatbot-rust`. The design of that
   loop follows Codex (`openai/codex`, `codex-rs`), the most complete open Rust
   agent stack, adapted for a multi-user, privacy-classified, encrypted web service.
3. **Harnesses as a bridge.** Some subscriptions may only be used through their
   vendor's harness, and wrapped harnesses give earlier access to mature tools.
   Adapters normalize them into the same event model. They are a stop-gap, not
   the architecture.
4. **Durability.** Runs are server-owned objects that survive browser disconnects
   and, from phase 2, server restarts. Every event is persisted before it is
   broadcast.
5. **Privacy is enforced, not displayed.** Privacy eligibility, key custody and
   tenant isolation constrain every model call, tool call, harness and workspace.

## Non-goals

- Byte-for-byte Codex protocol compatibility. Codex's app-server is an adapter
  target (see `harness-adapters.md`), not the public API of this application.
- Sharing the operator's subscription credentials with other users.
- Running agent code inside the webserver process or giving the webserver
  container-engine authority.
- Realtime audio, plugin marketplaces, remote-control pairing and account-billing
  APIs from the Codex registry. They can be added later behind the same model.

## Vocabulary

| Term | Meaning |
|---|---|
| **Conversation** | An existing saved set (or guest chat). It may contain plain chat pairs and agent threads. |
| **Thread** | A durable agent session: ordered turns, model history, config snapshot. Codex: thread/session. |
| **Turn** | One user submission and all the model sampling and tool work it causes until the agent yields. |
| **Step** | One model sampling request inside a turn. A turn has one or more steps. |
| **Item** | A user-visible unit in a turn: user message, agent message, reasoning summary, command execution, file change, tool call, approval, subagent call. |
| **Run** | The live execution of a turn by a runtime (native loop or harness adapter). |
| **Runtime** | The engine that executes a thread: `native`, `opencode`, `codex`, `claude`, `acp`, `terminal`. |
| **Workspace** | A persistent filesystem + toolchain environment owned by one user, usually holding git repositories. Independent of any conversation. |
| **Environment** | A concrete execution target inside a workspace: a sandbox profile, cwd, and process namespace. |
| **Runner** | The process that hosts runtimes and tools for one user's workspace. |

## Design summary

```
 Browser / Capacitor / Android Auto
              │ HTTPS: REST + NDJSON event streams (existing durable transport)
              ▼
 ┌─────────────────────────── chatbot-server (control plane) ───────────────────────────┐
 │ auth · CSRF · per-request key · privacy eligibility · thread/turn API · approvals UI │
 │ encrypted event log (redb) · provider gateway · GitHub connection broker            │
 └──────────────┬─────────────────────────────────────────────────────┬────────────────┘
                │ mTLS / UDS, narrow runner protocol                  │ model calls via
                ▼                                                     │ provider gateway
 ┌──────── workspace manager (privileged, no webserver access) ───────┴────┐
 │ allocates per-user runner containers, volumes, network policy, quotas   │
 └──────────────┬──────────────────────────────────────────────────────────┘
                ▼
 ┌──────── per-user runner container ───────────────────────────────────────┐
 │ agent-runner: native loop tools (exec/PTY, apply_patch, fs, git, MCP)    │
 │ harness adapters (opencode serve, codex app-server, claude -p, ACP, PTY) │
 │ inner sandbox per command (bwrap + seccomp), worktrees under /work       │
 └──────────────────────────────────────────────────────────────────────────┘
```

The native agent loop runs in the control plane's address space as a library
(`chatbot-agent` crate) or in the runner, depending on the privacy decision in
`architecture.md` §6. In both placements the loop never executes tools locally:
every tool call crosses the runner protocol.
