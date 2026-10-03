# Documentation review (Phase 7)

## Scope and rules

- Covers every tracked prose doc (README files, `AGENTS.md`, `docs/`, deployment READMEs and this review ledger) and the code comments that describe behavior.
- A doc or comment that lags the code is fixed directly. The user is asked only when the code itself may be wrong.
- Completed plans are folded into their living doc and then deleted. The review ledger is condensed to its current state; git keeps the history.
- Evidence is a read of the doc claim against the cited code. Executor-side files (`test-executor/projects/*.json`) are outside this repository and are not verified.

## Retired documents

- `docs/privacy-and-agent-connections-plan.md`: the agent-connection security model and the unimplemented execution scope moved to `docs/design-privacy.md` ("User-owned coding-agent connections").
- `docs/tts-streaming.txt`: the current token/clip/replay contract moved to `docs/design.md` (Voice Mode → Webserver TTS surface). Retry and playback details were already in `docs/mobile-apps.md`.
- `docs/design-history-chunks.md`: the implemented layout moved to `docs/design-history-store.md` ("Chunked storage layout"). Where the proposal differs from the code (schema 2 vs 3, direct format-2 creation, thumb-only reads, atomic delete cleanup), it was not carried over.

## Findings

| ID | Doc / comment | Claim (as found) | Code | Severity |
| --- | --- | --- | --- | --- |
| DOC-001 | `docs/design-privacy.md:82, 86`; `docs/design.md:165` (Phase 1 lead) | "Data persisted to disk is guaranteed end-to-end encrypted"; "End-to-end encryption is guaranteed for all data persisted to disk" | The data is AEAD-encrypted at rest, but the server receives the key on every request (`chatbot-server/src/enc_key_cookies.rs:22–42`) and decrypts server-side (`chatbot-core/src/history/api.rs:215–240, 432–442`); `login.rs:128–135` can also derive the key server-side. "End-to-end" overstates this: it is encryption at rest without a standing server key. Neighbouring statements (`design-privacy.md:72, 78, 88`) describe that accurately. | Medium |
| DOC-002 | `docs/design-privacy.md:82, 92`; `docs/design-history-store.md:117`; `docs/design.md:165` (Phase 1 lead) | Plaintext snapshots are "wiped from RAM after a period of time" / "evicted and wiped after the idle TTL" | `SetCache` expiry is lazy: entries are removed on a later lookup or insert (`chatbot-core/src/history/cache.rs:112–123, 251–264`), and no timer or background task sweeps it (`chatbot-server/src/background.rs` touches only sessions and remember tokens). Removal drops an `Arc` without zeroizing (`cache.rs:104–107`), and other references can keep the plaintext alive. A byte budget (64 MiB) also bounds the cache but isn't documented. | Medium |
| DOC-003 | `docs/design-history-store.md:174, 199, 296–332, 368–380, 446–459, 762–835` (Phase 1 lead) | API sketches and plans presented beside an "Implemented" status: `trait HistoryStore`, `HistoryService::open_default`, public `SetId(pub Uuid)`, a ciphertext-holding `SetCache`/`CachedCipher`, `HistoryError` variants, and a PR 1–11 plan | None of those names exist as sketched: `RedbHistoryStore` is concrete (`history/store/mod.rs:179`), the constructors are `open`/`open_with_data_dir` (`history/api.rs:131, 139`), `SetId`'s field is private (`history/types.rs:13`), the cache holds plaintext `Arc<LogicalSnapshot>` (`history/cache.rs:36–45`), and the `HistoryError` shapes differ (`history/api.rs:42–57`). The provider half of the lead is resolved: no doc still describes trait-based providers. | Low |
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
| DOC-016 | `.config.yml.example:46–78` | The provider examples omit the per-provider keys `allowed_providers` and `request_timeout` | Both are accepted (`chatbot-core/src/config.rs:132–135`); `request_timeout` defaults to 300 s (`chatbot-server/src/providers/openai.rs:82, 130`) and `allowed_providers` constrains routing (`openai.rs:183–188`). Undocumented, not wrong. | Low |

Rejected leads: `docs/design.md:215` names `NativeMicUtteranceVAD` without placing it in `chat.js` (it lives in `static/voice-capture.js:39`). `docs/design-privacy.md:150` correctly says coding-agent execution is unimplemented; connection management (`chatbot-server/src/lib.rs:401–403`) is a separate, implemented feature. `docs/design-history-store.md`'s legacy references to `persistence.rs` and `session.rs` still resolve and are labelled legacy. `static/deps/README.md` versions match the vendored file banners. Every other key and comment in `.config.yml.example`, `.env.example`, `docker-compose.yml`, the Dockerfile, the compose overrides and the Helm chart matches the code.

Not findings: `docs/mobile-apps.md:394–406` and `docs/audio-decoder-check.md:98` use the operator's own host paths for host-only steps; they stay as written.

## Comment findings

`HISTORY` marks a comment that narrates past behavior instead of describing current code; the project rule is that such comments go unless they guard against a real regression.

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
| DOC-C10 | `chatbot-core/src/config.rs:136–141` | WRONG: `rate_limit_retries` "Defaults to 1"; `rate_limit_max_wait_secs` "Defaults to 5" | The defaults applied are `DEFAULT_RATE_LIMIT_RETRIES = 5` (`chatbot-server/src/providers/openai.rs:22`) and a 30 s wait cap (`openai.rs:26`), matching `.config.yml.example:65–66` and `docs/design.md`. | Medium |

Coverage: every non-test comment block was extracted with its following code (core 516, server 352, browser JS 425, Android 256, Python 83). All were read by a reviewer, and the claims were spot-checked against the source. A deterministic pass also checked every backtick-quoted identifier in a comment against the code (one miss, DOC-C06) and swept for history wording. An itemized rerun listed about 300 server claims checked, prioritizing auth, cookies, CSRF, privacy and providers, and found nothing new. The Android and Python reviewer listed 112 Android and 47 Python claims it checked. The JS reviewer reported no problems, but its line citations were unreliable, so that clean result rests on the deterministic checks.

## Resolution

All DOC-001–016 and DOC-C01–C10 findings are fixed. Documentation and comments follow the implemented behavior; DOC-002 required changing cache code to provide the documented sweep and zeroization behavior.

- **DOC-001 and DOC-002 (privacy wording and TTL wipe):** `design-privacy.md`, `design.md` and `design-history-store.md` now say plainly that this is not end-to-end encryption, because the LLM works on plaintext, but it is as close to it as this stack allows. Data is encrypted at rest, and the server holds the key only during active requests (`9dedc1b`). For DOC-002 the code changed: the background purge (every `SESSION_PURGE_INTERVAL_SECS`, default 300 s) now sweeps expired `SetCache` entries and summaries, and `LogicalSnapshot` zeroizes its strings on drop (`a3fac32`). Red-first regressions:
  - `purge_expired_removes_only_expired_entries_and_summaries`;
  - `zeroize_tests`;
  - `history_cache_purge_does_not_open_unopened_history` (the purge never opens an unopened database).

  Red job `20261003T193304-4aeac47c9ad9`; green jobs `20261003T195840-c82b77d2eef4`, `20261003T200032-dbfdb643edf9` and `20261003T200040-8830505ab71b`. The docs state the remaining limits: a sweep deadline of TTL plus up to one purge interval, and zeroization only of memory the cache owned.
- **DOC-003 to DOC-016 (living docs and instructions):** fixed in `1f52d28`.
  - `design.md` describes the three privacy modes as current, and the provider-docs item is ticked.
  - The README describes encrypted history with in-memory sessions and the `testctl` entry point.
  - `AGENTS.md` dropped the `temp/todo.md` instruction.
  - `mobile-apps.md` places the VAD in `voice-capture.js` and marks rebuilds as host-only operator steps.
  - `.config.yml.example` documents `allowed_providers` and `request_timeout`.
  - `design-history-store.md` was rewritten to match the code: schema 3, chunked storage, the plaintext snapshot cache and the real API names. The unimplemented sketches and the PR plan were replaced by a short "Not implemented" section.
- **DOC-C01 to DOC-C10 (comments):** history narration was removed or restated as current behavior.
  - The `chat_images.rs` comment stays as a present-tense gotcha because it guards a real regression (image data URLs counted as text drop the newest image).
  - DOC-C08 and DOC-C10 now state the actual stream-error and rate-limit behavior.
  - DOC-C09 now says the job runner catches `Exception`, not `BaseException`. The runner is unchanged.

## Completion

Phase 7 covered the 26 tracked prose files, every non-test code comment (about 1,600 blocks across Rust, JS, Java and Python), and configuration and deployment comments. Three completed plans were folded into living docs and deleted: `privacy-and-agent-connections-plan.md`, `tts-streaming.txt` and `design-history-chunks.md`. The review ledger was condensed from 2,289 to about 560 lines. All relative links and anchors resolve. Phase 7 is complete, with all findings fixed. DOC-002 also changed the history-cache background sweep and zeroization code. The suite gate is `20261003T210405-6ec64fba7bc9` (151 nonzero Rust test-result blocks; 1,171 passed, 0 failed; nested DNS 34 and voice 70 Python tests reported separately).
