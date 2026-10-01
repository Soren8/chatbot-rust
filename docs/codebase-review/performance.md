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

## Session 085 — voice-pipeline and client inventory (leads, unmeasured)

Read: `chatbot-server/src/stt.rs` 1–367, `tts.rs` 1–585, `tts_opus.rs` 20–140, `tts/backend.rs` 1–80 plus route URLs; `static/tts-playback.js` 67–205, 456–612, 719–800; `static/activity-sync.js` 125–225; `static/chat.js` 2380–2425, 3690–3790; `static/chat-renderer.js` structure; `chatbot-cuda/src/main.py` 140–200, `service.py` structure and 579–600. Android N02/N03 and page-load reads (PERF-001) are not yet inventoried.

| Lead | Path | Observation | Proposed measurement |
| --- | --- | --- | --- |
| PERF-010 | `tts.rs:152–161`, `stt.rs:156–165` | Every set-bound `POST /tts` (one per spoken sentence) and every bound `/stt` calls `HistoryService::load`, fully materializing the set's images, only to read `privacy_level`. With PERF-002, a voice turn performs one STT, two chat and N sentence materializations. | Image-blob opens per bound `/tts` and `/stt`; materializations per N-sentence voice turn. |
| PERF-011 | `tts.rs:309–433`, `tts/backend.rs:213`, `chatbot-cuda/src/main.py:91–138` | Synthesis starts only on `GET /tts_stream`, requests the whole-clip Kokoro endpoint although the service exposes a streaming one, then Opus-encodes the whole clip inline on the async runtime before the first byte. Time to first audio = admission RTT + stream RTT + full synthesis + full encode. | Server-side time from `GET /tts_stream` to first response byte with a fake backend of fixed per-sentence latency; encode time per audio second. |
| PERF-012 | `tts-playback.js:549–560, 181–188` | Desktop playback prefetches exactly one sentence ahead (native: up to four); with per-sentence synthesis latency above clip duration, gaps appear between sentences. | Gap count/duration in the desktop queue fixture with injected synthesis latency. |
| PERF-013 | `tts-playback.js:458–479, 724–736` | Sentence discovery re-splits the entire response text on every text-change notification: O(length²) per response. | `split` input characters per K-chunk response in the queue fixture. |
| PERF-014 | `tts-playback.js:530–537` | While generating, an idle desktop queue polls every 60 ms in addition to source subscriptions. | Timer wakeups per second during a generation with no new sentence. |
| PERF-015 | `chat.js:3744–3760, 2410–2425`, `chat-renderer.js:270–346` | Each streamed delta re-parses the full accumulated Markdown (with highlight.js, including `highlightAuto`) and replaces the bubble's HTML, rewrites `data-original` with the full text and republishes playback text, with no frame coalescing: O(length²) CPU per response, the main mobile/WebView cost. | `renderMarkdown` calls and characters parsed per K-delta response in the Node-vm harness; WebView frame cost is a device limit. |
| PERF-016 | `activity-sync.js:140–172` | Per NDJSON line: timer cancel/reschedule and `buffer.slice` of the remainder (O(lines²) per chunk). Minor beside PERF-015. | Timer operations per event. |
| PERF-017 | `chatbot-cuda/src/main.py:144–167` | The `/v1/stt` handler runs the ffmpeg conversion and temp-file write synchronously inside an `async def`, blocking the event loop (and concurrent TTS stream delivery) for the conversion's duration. | Python test: concurrent request latency during a slow fake converter. |

## Batch PERF-A — privacy checks read only the policy (PERF-002, PERF-010)

`HistoryService::privacy_level` reads the sealed set policy under the same content permit; `/chat`, `/regenerate`, bound `/stt` and bound `/tts` use it instead of `HistoryService::load`. `chatbot_core::history::cost` adds thread-local counters of pair/image/thumbnail blob opens for cost-bound tests. `privacy_read_cost` red (job `20261001T003706-ce1b0d7bc42f`: bound `/tts` and `/stt` each opened 3 pairs + 3 images for a 3-image set; `/chat` exceeded one materialization) → green (`20261001T003744-9844a2052429`). Regression targets `voice_privacy` 10/10, `set_privacy` 1/1, `privacy_policy` 8/8 passed. A bound voice turn no longer materializes the set once per sentence.

## Batch PERF-B — prompt preparation proportional to what is sent (PERF-001 prepare path, PERF-003, PERF-004)

Authenticated prepare loads the ref-shaped logical snapshot (cache-served) instead of materializing every image; the capture and context keep `[IMAGE:img:…]` refs, which commit already normalizes. `prepare_prompt_messages_with` plans images first (full-resolution slots resolved through an `ImageResolver`, others become pending thumbnails with the fixed thumbnail estimate), truncates, then produces thumbnails only for kept pairs, using each image's stored 384px thumbnail as the source (256px q55 output unchanged in size/quality; pixels may differ slightly from a resize of the original). Regenerate coalesces the edit against the materialized target pair only, so the resent user text is byte-identical to before. One working history copy replaces the strip/rewrite clones.

Known edge: an inline (guest) image whose thumbnail fails is budgeted as a thumbnail during truncation and becomes the omitted-image placeholder afterwards; the old order budgeted the placeholder text. This only makes truncation more conservative in that failure case.

Evidence: `history_read_cost` red (`20261001T004323-180566cd197d`: `/chat` and `/regenerate` opened all 3 images) → green (`20261001T004805-ec34dccba844`: 1 full image + 2 stored thumbnails each). New core unit `stored_image_refs_resolve_only_the_renditions_kept_pairs_send` pins resolver calls (a truncated pair's image is never read). Full suite `20261001T004845-3604b296f507`: 1,082 passed, 0 failed (`temp/test-logs/phase5-batchB-full.log`).
