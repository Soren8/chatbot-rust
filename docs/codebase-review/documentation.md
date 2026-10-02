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
| DOC-001 | `docs/design-privacy.md:17–20, 75, 79` (lead from Phase 1, `findings.md`) | Default mode labelled "Zero-Knowledge"; disk persistence called "end-to-end encrypted" | The server receives the key and decrypts during requests (same doc `:60–65, 81`; `chatbot-core/src/session.rs` key verification and history operations). | Pending re-check |
| DOC-002 | `docs/design-privacy.md` plaintext-cache wording (lead from Phase 1) | Promises timed plaintext wiping | `SetCache` uses lazy expiry checks and capacity eviction with ordinary removal; no timer or zeroization (`chatbot-core/src/history/cache.rs`). | Pending re-check |
| DOC-003 | Provider and history design docs (lead from Phase 1) | Provider trait claims vs concrete dispatch; chunking design labelled Draft; old history design mixes implemented and proposed interfaces | The chunking proposal is retired (see above); provider and history wording still to be re-checked. | Pending re-check |
| DOC-004 | `docs/design.md:188` | "Saved sets currently support **Private** … and **Non-private**. The next policy model adds **Standard**." | Three levels are implemented: `chatbot-core/src/config.rs:90–94` `PrivacyLevel`, and the UI offers all three (`static/templates/chat.html:122`, `static/chat.js:1243`). The rest of the same bullet already describes the three-level model. | Medium |
| DOC-005 | `docs/design.md:190` | "Shared chat UI currently shows the two implemented modes" | The UI renders Private, Standard and Non-private (`static/templates/chat.html:122`). Contradicts `docs/design-privacy.md:15`. | Medium |
| DOC-006 | `README.md:3` | "manages chat history and sessions encrypted securely on disk" | Sessions are in-memory (`chatbot-core/src/session.rs`; `docs/design.md:96`); only chat history is encrypted on disk (redb). | Medium |
| DOC-007 | `docs/design.md:201` | Unchecked: "Document provider-specific fields (e.g., base URLs) and include example configs." | `.config.yml.example:65–66` documents provider fields such as `rate_limit_retries` and `rate_limit_max_wait_secs`, matching `chatbot-core/src/config.rs:139, 143`. | Low |
| DOC-008 | `README.md:15` | "Comprehensive integration tests (`cargo test`)" | Tests run inside the test image through `testctl` (`AGENTS.md:11, 31–34`); `cargo test` on the host is not the supported entry point. | Low |
| DOC-009 | `AGENTS.md:53–55` | "Use `temp/` for ephemeral notes"; "Keep `temp/todo.md` updated" | `AGENTS.md:27` reserves `temp/` for caches and logs; no code or workflow reads `temp/todo.md`. Internal inconsistency in the agent instructions. | Low |
| DOC-010 | `docs/mobile-apps.md:155, 239, 280` | `NativeMicUtteranceVAD` "in `chat.js`" / "(chat.js)" | Defined in `static/voice-capture.js:39` (exported `:426`); `static/chat.js:4535` only constructs it. | Low |
| DOC-011 | `docs/mobile-apps.md:17, 215` | `docker compose up --build -d webserver` given as the rebuild step | The `webserver` service exists (`docker-compose.yml:43`), but `AGENTS.md:34–36` makes rebuilds host-only and forbids agents from running them; the doc doesn't say so. | Medium |
| DOC-012 | `docs/design-history-store.md:618` | "redb `META[\"schema\"] = 1`" | `SCHEMA_VERSION` is 3 (`chatbot-core/src/history/store/tables.rs:46`). | Medium |
| DOC-013 | `docs/design-history-store.md:620` | "**Phase 2 (started):** split `SETS_BLOB` into …" | Chunked storage is implemented: `BlobFormat::AeadChunkedV2` and lazy migration (`chatbot-core/src/history/api.rs:180–209`, `history/store/chunks.rs:441–564`). | Low |
| DOC-014 | `docs/design-history-store.md:25` | "Phase 1 stores one whole-set encrypted payload per `set_id`" (presented as the storage model) | New sets start as whole-set format 1 (`history/store/mod.rs:621–660`) but are split into chunks on the first payload operation; the overview omits that. | Low |
| DOC-015 | `docs/design-history-store.md:109` | "this design is the source of truth until [code lands]" | The code has landed (status row at `:13` says "Implemented (cutover complete)"). | Low |

Rejected leads: `docs/design.md:215` names `NativeMicUtteranceVAD` without placing it in `chat.js` (it lives in `static/voice-capture.js:39`). `docs/design-privacy.md:150` correctly says coding-agent execution is unimplemented; connection management (`chatbot-server/src/lib.rs:401–403`) is a separate, implemented feature. `docs/design-history-store.md`'s legacy references to `persistence.rs` and `session.rs` still resolve and are labelled legacy. `static/deps/README.md` versions match the vendored file banners.

Not findings: `docs/mobile-apps.md:394–406` and `docs/audio-decoder-check.md:98` use the operator's own host paths for host-only steps; they stay as written.

## Comment findings

`HISTORY` marks a comment that narrates past behavior instead of describing current code; the project rule is that such comments go. Per the user's decision they are recorded here, not edited.

| ID | Comment | Problem | Code | Severity |
| --- | --- | --- | --- | --- |
| DOC-C01 | `chatbot-core/src/config.rs:448` | HISTORY: "Insecure placeholder previously used when `SECRET_KEY` was unset." | A missing `SECRET_KEY` now panics (`config.rs:452–470`); the constant only feeds `FORBIDDEN_SECRET_KEYS`. | Low |
| DOC-C02 | `chatbot-core/src/chat_images.rs:75–77` | HISTORY: "…was causing history truncation to strip the latest image." | Image payloads get fixed estimates (`chat_images.rs:97–104`). | Low |
| DOC-C03 | `chatbot-core/src/history/ops.rs:664–665` (test) | HISTORY: "previously rejected by a 1M-char history max at finalize" | The limit is `5 * 1024 * 1024` (`ops.rs:9–14`). | Low |
| DOC-C04 | `chatbot-server/src/http_error.rs:21` | HISTORY: "5xx api_error callers previously logged nothing…" | `api_error` logs 5xx at ERROR (`http_error.rs:20–25`). | Low |
| DOC-C05 | `chatbot-server/src/memory.rs:287` | HISTORY: "AI text is no longer required for the check…" | The match uses `pair_index` + `user_message` only (`memory.rs:279–329`). | Low |
| DOC-C06 | `chatbot-server/src/generation_deps.rs:64` | MISSING-REF + HISTORY: "Matches the previous `home::build_available_models` filtering." | No such function exists; filtering lives in `home.rs:279` `build_available_models_from_summaries`. | Low |
| DOC-C07 | `chatbot-server/src/generation_deps.rs:24–26, 230–232` | HISTORY: "preserves the original lazy boundaries"; "capture this at the old site … matching the original eager `app_config()` read" | Describes the refactor's origin rather than current behavior; the current behavior (one capture per call) is stated alongside it. | Low |
| DOC-C08 | `chatbot-cuda/src/main.py:7` | WRONG: module doc gives TTS error shapes as "400/500" | The stream route (`main.py:113–139`) raises `HTTPException(500)` inside the `StreamingResponse` generator. After the first chunk the status is already sent, so a mid-stream failure ends the stream instead of returning 500. | Medium |
| DOC-C09 | `chatbot-cuda/src/service.py:206` | WRONG: "Run, clean up, unregister, then settle; never raises." | `_run_job` catches `Exception` only (`service.py:479–494`); a `BaseException` from the job skips cleanup, unregister and settlement. | Low |

Coverage: every non-test comment block was extracted with its following code (core 516, server 352, browser JS 425, Android 256, Python 83). All were read by a reviewer, and the claims were spot-checked against the source. A deterministic pass also checked every backtick-quoted identifier in a comment against the code (one miss, DOC-C06) and swept for history wording. The Android and Python reviewer listed 112 Android and 47 Python claims it checked. The JS reviewer reported no problems, but its line citations were unreliable, so that clean result rests on the deterministic checks.
