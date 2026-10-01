# Performance and resource-use review (Phase 5)

## Session 085 — scope and method, 2026-10-01

Baseline: `refactor@247c875`. The `no-dns-sidecar` test branch is deleted; X01 remains in the tree and in scope.

### Agreed scope

- Whole-repository Perf column, with priority on **chat latency** (admission → first token, per-turn history load/decrypt, prompt building, image packing, settlement/save), **client/mobile cost** (per-chunk browser/WebView work, re-rendering, retry/backoff and reconnection loops, timers, wake locks, battery), and the **voice pipeline** (STT upload, per-sentence TTS admission/round trips, Opus encoding, GPU service queuing and job lifetime). Unbounded RAM growth is covered as ordinary review scope, not a priority.
- Aggressive remediation: storage layout and API changes are allowed when measurement shows they are worthwhile. PERF-001 (whole-history materialization for page/pair reads and prepare) is in scope for redesign on that condition.

### Evidence standard

Static reading produces leads. A lead becomes a remediable finding only after a deterministic measurement through `testctl`: call/load counts, bytes copied or decrypted, allocation or buffer sizes, round-trip counts, timer/wakeup counts, or wall-clock comparisons with stated noise bounds. A measurement that needs a GPU, a device or the live host is recorded as an evidence limit rather than inferred. Instrumentation added to make a measurement repeatable becomes a permanent regression or characterization test where it pins the improved bound.

Each fix follows the program rules: a failing test that captures the cost bound (or a characterization test before a restructuring), bounded batches agreed with the user, the primary reviewer reading every diff, and one passing full suite (plus an APK build when native code changes) as the phase gate.

### Known leads entering the pass

- PERF-001 (`modularity.md` cross-pass table): `load_page`/`load_pair` load every logical pair before slicing; session prepare materializes full history before image packing.
- MOD-005 verification note: projection/clone costs in the history facade must be measured, not assumed.
- Post-Phase-4 durable activity: per-generation RAM event buffers, 24-hour operation/TTS/STT receipts, NDJSON views with five-second heartbeats and 20-second client reconnect, and client backoff/coalescing triggers.

## Session 085 — chat-latency inventory (leads, unmeasured)

Read: `chatbot-server/src/chat.rs` 1–487, `generations.rs` 1–598; `chatbot-core/src/session.rs` 670–1000, 1730–1900, 2463–2580; `history/api.rs` 200–460, 800–880; `history/store/chunks.rs` 133–200, 540–700; `chat.rs` (core) 140–330; `chat_images.rs` 150–260, 384–455; `user_store.rs` 138–180, 330–375. Each lead below is a candidate for measurement, not a confirmed finding.

| Lead | Path | Observation | Proposed measurement |
| --- | --- | --- | --- |
| PERF-002 | `server/chat.rs:296–298`, `session.rs:836–860` | An authenticated turn calls `HistoryService::load` (full materialization: decrypt every image, inline base64) only to read `privacy_level`; prepare then calls `load` again. Two full materializations per turn. | Count image-blob opens and bytes materialized per `/chat` for a set with N images. |
| PERF-003 | `core/chat.rs:183–200`, `chat_images.rs:163–182` | `prepare_history_images` runs over the whole untruncated history every turn; every image beyond `MAX_FULL_RES_IMAGES` is decoded, resized and JPEG-re-encoded, including pairs later dropped by `truncate_history`. Stored thumbnails are not reused. | Count thumbnail encodes and wall-clock per turn versus N history images. |
| PERF-004 | `core/chat.rs:183–235`, `chat_images.rs:167–171`, `session.rs:953–963` | The materialized history (with inline image data) is cloned by capture, context build, think-stripping, image rewriting, truncation and message construction. | Bytes allocated per turn for a fixed history. |
| PERF-005 | `chunks.rs:625–660` | `commit_chunked` opens a read transaction and decrypts every existing pair to detect changes, so each append costs O(history) decrypts. | Pair-blob opens per append versus history length. |
| PERF-006 | `generations.rs:563–582` | Each viewer rescans and clones the entire event buffer under the worker's state mutex after every event: O(events²) per generation per viewer, contending with `emit`. | Events cloned per viewer for a K-chunk generation. |
| PERF-007 | `generations.rs:293, 528` | One global `AsyncMutex` is held across the whole legacy handler (key check, history loads, image work, privacy-permit await). Admissions for all users and every Stop serialize behind it. | Concurrent admission/Stop latency with an injected slow prepare. |
| PERF-008 | `generations.rs:115–138, 594–598` | One NDJSON event (repeating the 32-char id and channel) per provider chunk, cloned for buffer and broadcast. Client cost scales with chunk count. | Events and bytes per generation for a token-per-chunk provider fixture; client cost measured in the W-unit pass. |
| PERF-009 | `generations.rs:163–165`, `session.rs:731–756`, `user_store.rs:138–170` | Every replay sweeps all receipts; every events/status/activity request re-opens the user store (three directory checks) and reads the verifier file twice. Small per call; relevant to reconnect storms. | Syscalls/file reads per events request. |
