# Current State and Gap Analysis

Snapshot of `chatbot-rust` relevant to an agent platform, with the gaps each
later document closes.

## Backend

### Crates and ownership

- `chatbot-core` owns business rules: prompt assembly and context truncation
  (`chat.rs`: `prepare_prompt_messages`, `prepare_chat_messages`,
  `strip_think_tags`), session state and generation leases (`session.rs`,
  `ChatService`), encrypted history (`history/` with `api.rs`, pure `ops.rs`,
  sealed `store/`, `crypto.rs`), configuration, privacy levels, and encrypted
  agent-connection records with egress validation (`agent_connections.rs`,
  `agent_egress.rs`).
- `chatbot-server` adapts HTTP: chat and regenerate handlers, the durable
  generation registry (`generations.rs`), providers (`providers/`), Brave search
  (`search.rs`, `brave.rs`), agent connections, idempotency, policy and the Axum
  router (`lib.rs`). `AppServices` (`services.rs`) owns injected dependencies.

### Model access

- Providers are a closed enum: OpenAI-compatible and xAI. Provider config holds
  identity, type, model, context size, endpoint, key, retry bounds and search
  settings.
- Tool use is limited to search. The Brave flow streams until the model emits a
  `brave_web_search` call, runs the search, injects up to 8,000 characters of
  results as a user message, and streams a follow-up. Tool-aware streaming falls
  back to a plain stream if it fails before any content was sent. xAI may use its
  native `web_search`; privacy policy can forbid that fallback.
- There is no general tool registry, no tool-result message role in the prompt
  DTO, no multi-step sampling loop and no parallel tool calls.

### Durable generations

- Opt-in with `X-Generation-Mode: durable`, `set_id`, `expected_version` and an
  `Idempotency-Key`. Admission returns 202, `X-Generation-Id` and an NDJSON view.
- A worker owned by `AppServices` holds the provider stream, the privacy permit,
  the reservation and the admitting request's data key, for at most 30 minutes.
- Events: `{generation_id, seq, type, channel: answer|thinking, text}`; heartbeat
  every 5 s; buffer capped at 4 MiB / 8,192 events; finished entries are kept for
  a replay grace period. Routes are owner-scoped.
- The registry is RAM-only. A process restart loses active work and replay
  history. Admission is serialized and allows one active generation per set.

### History and encryption

- redb store, AES-256-GCM with random 96-bit nonces, HKDF-SHA256 subkeys from the
  user's data key, AAD binding owner, set id, blob kind/format and set version.
- Mutations are pure transforms committed with compare-and-swap on set version.
- The data key is client-derived and arrives per request (HttpOnly cookie or
  `X-Enc-Key`), validated against an HMAC verifier and zeroized afterwards. The
  server holds no standing key. Background work cannot decrypt history unless a
  request supplied the key.
- A set stores chat *pairs* (user text + assistant answer, optional images).
  There is no representation for tool calls, multi-item turns or nested runs.

### Privacy

- Levels `private < standard < non_private`. A task may use a destination at its
  level or stricter. Providers default to `non_private`; sets default to `private`.
- A shared in-process coordinator holds content permits through outbound work
  and blocks privacy-mode changes during active work (`409 privacy_busy`).

### Agent connections

- Per-user encrypted OpenCode connection records (URL + Basic credentials sealed
  with the data key, AAD = owner + record id + revision), fixed `non_private`.
- CRUD under `/agent_connections` and `POST /agent_connections/{id}/check`, which
  calls only `/global/health` with DNS pinning, forbidden-IP rejection, no
  redirects, no proxy, a 2-slot semaphore, a per-user rate limit and a 10 s
  timeout. No prompts, sessions or files are ever sent. There is no execution.

## Frontend

- Server-rendered Minijinja (`home.rs`, `static/templates/chat.html`) plus
  vanilla UMD JavaScript modules with explicit dependencies:
  `activity-sync.js` (durable start/attach/replay/stop/recover, sequence gaps,
  exponential backoff, 20 s silence timeout), `conversation-state.js`
  (set-version and generation fencing), `chat-renderer.js` (safe DOM builders),
  `session-client.js` (CSRF and 401 retry), `chat.js` (coordinator).
- `activity-sync.js` collapses durable events back into a text stream with
  `<think>` blocks so the old renderer can consume it. Rendering is therefore
  string-oriented: there is no per-item DOM model.
- Android uses a Capacitor WebView; Android Auto is a native `VoiceScreen`
  (`PaneTemplate`) speaking `DurableVoiceProtocol`.
- JavaScript tests are Rust tests that run Node fixtures under
  `chatbot-server/tests/fixtures`.

## Gaps

| # | Gap | Closed by |
|---|---|---|
| G1 | No agent loop: one sampling request per answer, no tool results in history, no follow-up decision | `agent-loop.md` |
| G2 | No tool registry, no exec/patch/fs tools, no approvals, no sandbox | `tools.md` |
| G3 | History stores pairs, not threads/turns/items | `events-and-storage.md` |
| G4 | Durable events are RAM-only, text-only, two channels | `events-and-storage.md` |
| G5 | No filesystem, repositories, worktrees or GitHub identity | `workspaces-git.md` |
| G6 | No execution host; webserver must never gain engine authority | `architecture.md` |
| G7 | Agent connections cannot submit work or observe events | `harness-adapters.md` |
| G8 | Provider layer lacks the Responses/Messages tool-calling shapes, reasoning items, prompt caching, usage accounting | `agent-loop.md` §4 |
| G9 | Per-request key custody blocks unattended Private runs | `architecture.md` §5 |
| G10 | Renderer collapses everything into text | `ui.md` |

## Assets to keep

- The durable activity contract (connections are disposable views; dropped
  connections never cancel work or duplicate turns) becomes the run contract.
- Idempotency receipts, owner-scoped routes and CAS mutations carry over.
- The privacy eligibility lattice and fail-closed egress validator extend to
  every outbound path an agent opens.
- The AEAD/AAD discipline extends to event-log records.
- The explicit-dependency JS module style and Node-fixture tests extend to the
  new event reducer and item renderers.
