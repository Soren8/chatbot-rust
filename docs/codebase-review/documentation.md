# Documentation review (Phase 7)

## Scope and rules

- Covers every tracked prose doc (README files, `AGENTS.md`, `docs/`, deployment READMEs and this review ledger) and the code comments that describe behavior.
- Per the user's decision, a doc or comment that contradicts the code is **recorded here and left unchanged**. Neither side is edited; the user decides which is right.
- Completed plans are folded into their living doc and then deleted. The review ledger is condensed to its current state; git keeps the history.
- Evidence is a read of the doc claim against the cited code. Executor-side files (`test-executor/projects/*.json`) are outside this repository and are not verified.

## Retired documents

- `docs/privacy-and-agent-connections-plan.md`: the agent-connection security model and the unimplemented execution scope moved to `docs/design-privacy.md` ("User-owned coding-agent connections").
- `docs/tts-streaming.txt`: the current token/clip/replay contract moved to `docs/design.md` (Voice Mode → Webserver TTS surface). Retry and playback details were already in `docs/mobile-apps.md`.
- `docs/design-history-chunks.md`: the implemented layout moved to `docs/design-history-store.md` ("Chunked storage layout"). Where the proposal differs from the code (schema 2 vs 3, direct format-2 creation, thumb-only reads, atomic delete cleanup), it was not carried over.

## Findings

| ID | Doc / comment | Claim | Code | Severity |
| --- | --- | --- | --- | --- |
| DOC-001 | `docs/design.md:188` | "Saved sets currently support **Private** … and **Non-private**. The next policy model adds **Standard**." | Three levels are implemented: `chatbot-core/src/config.rs:90–94` `PrivacyLevel`, and the UI offers all three (`static/templates/chat.html:122`, `static/chat.js:1243`). The rest of the same bullet already describes the three-level model. | Medium |
| DOC-002 | `docs/design.md:190` | "Shared chat UI currently shows the two implemented modes" | The UI renders Private, Standard and Non-private (`static/templates/chat.html:122`). Contradicts `docs/design-privacy.md:15`. | Medium |
| DOC-003 | `README.md:3` | "manages chat history and sessions encrypted securely on disk" | Sessions are in-memory (`chatbot-core/src/session.rs`; `docs/design.md:96`); only chat history is encrypted on disk (redb). | Medium |
| DOC-004 | `docs/design.md:201` | Unchecked: "Document provider-specific fields (e.g., base URLs) and include example configs." | `.config.yml.example:65–66` documents provider fields such as `rate_limit_retries` and `rate_limit_max_wait_secs`, matching `chatbot-core/src/config.rs:139, 143`. | Low |
| DOC-005 | `README.md:15` | "Comprehensive integration tests (`cargo test`)" | Tests run inside the test image through `testctl` (`AGENTS.md:11, 31–34`); `cargo test` on the host is not the supported entry point. | Low |
| DOC-006 | `AGENTS.md:53–55` | "Use `temp/` for ephemeral notes"; "Keep `temp/todo.md` updated" | `AGENTS.md:27` reserves `temp/` for caches and logs; no code or workflow reads `temp/todo.md`. Internal inconsistency in the agent instructions. | Low |
| DOC-007 | `docs/mobile-apps.md:155, 239, 280` | `NativeMicUtteranceVAD` "in `chat.js`" / "(chat.js)" | Defined in `static/voice-capture.js:39` (exported `:426`); `static/chat.js:4535` only constructs it. | Low |
| DOC-008 | `docs/mobile-apps.md:17, 215` | `docker compose up --build -d webserver` given as the rebuild step | The `webserver` service exists (`docker-compose.yml:43`), but `AGENTS.md:34–36` makes rebuilds host-only and forbids agents from running them; the doc doesn't say so. | Medium |
| DOC-009 | `docs/design-history-store.md:618` | "redb `META[\"schema\"] = 1`" | `SCHEMA_VERSION` is 3 (`chatbot-core/src/history/store/tables.rs:46`). | Medium |
| DOC-010 | `docs/design-history-store.md:620` | "**Phase 2 (started):** split `SETS_BLOB` into …" | Chunked storage is implemented: `BlobFormat::AeadChunkedV2` and lazy migration (`chatbot-core/src/history/api.rs:180–209`, `history/store/chunks.rs:441–564`). | Low |
| DOC-011 | `docs/design-history-store.md:25` | "Phase 1 stores one whole-set encrypted payload per `set_id`" (presented as the storage model) | New sets start as whole-set format 1 (`history/store/mod.rs:621–660`) but are split into chunks on the first payload operation; the overview omits that. | Low |
| DOC-012 | `docs/design-history-store.md:109` | "this design is the source of truth until [code lands]" | The code has landed (status row at `:13` says "Implemented (cutover complete)"). | Low |

Rejected leads: `docs/design.md:215` names `NativeMicUtteranceVAD` without placing it in `chat.js` (it lives in `static/voice-capture.js:39`). `docs/design-privacy.md:150` correctly says coding-agent execution is unimplemented; connection management (`chatbot-server/src/lib.rs:401–403`) is a separate, implemented feature. `docs/design-history-store.md`'s legacy references to `persistence.rs` and `session.rs` still resolve and are labelled legacy. `static/deps/README.md` versions match the vendored file banners.

Not findings: `docs/mobile-apps.md:394–406` and `docs/audio-decoder-check.md:98` use the operator's own host paths for host-only steps; they stay as written.
