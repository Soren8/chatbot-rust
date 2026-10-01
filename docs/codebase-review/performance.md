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

## Batch PERF-C — streaming client cost (PERF-013, PERF-014, PERF-015)

- PERF-015: `createFrameRenderer` coalesces each streaming bubble's Markdown and thinking-text renders to one per animation frame (immediate where frames are unavailable). Every terminal path flushes; a render is skipped once its request is no longer live, so a voice interrupt's `[Stopped]` suffix or error chrome is never overwritten. Fixture scenarios `chat-render-coalescing` and `regen-render-coalescing`: red (`20261001T005915-5a9e176535aa`, 20 chunks rendered 20 times) → green (`20261001T010106-6d6dfd9bffca`, one render per frame plus the end-of-stream flush).
- PERF-013: desktop and native sentence discovery split only from the start of the last queued sentence (native keeps index tracking when a splitter reports no offsets). Characterization `incremental`: red (`20261001T010357-c33ee3b86351`, 565,695 characters split for a 5,689-character, 200-sentence reply) → green (`20261001T010513-df6bb31378e5`) with spoken text unchanged on both queues.
- PERF-014: while a source subscription exists, desktop (60 ms) and native (80 ms) idle polls become a 1 s backstop; notifications and clip consumption remain the wake signals. The MOD-era source pin in `playback_source_boundary.rs` was updated to this contract (both fallbacks retained without a subscription).

Full suite on the batch tree (`20261001T010928-249729e38fe6`): 1,077 passed, 1 failed — `chatbot-cuda` `test_shared_deadline_bounds_and_retains_busy_workers` (`active_stream_count` 0 != 1), a timing-dependent shutdown test in code this batch does not touch; it passed 64/64 on two immediate reruns (`20261001T012012-d51156f75c4f`, `20261001T012038-073324fa8c1f`). Recorded as a test-quality (Phase 6) flake lead. WebView frame timing and battery effect are device limits.

## Batch PERF-D — generation views, admission and commit (PERF-005, PERF-006, PERF-007)

- PERF-006: `State::events_after` slices the contiguous event buffer by sequence instead of filtering every buffered event after each delivered event (O(1) offset plus the new events, under the same mutex). Unit `events_after_slices_the_contiguous_buffer_by_sequence` pins evicted-prefix, middle, end and past-end cursors.
- PERF-007: admission and Stop serialize per owner (`admission_lock`), not on one global lock held across another user's whole prepare. Receipts and running-generation checks are owner-scoped, so cross-owner ordering carried no invariant. Unit `admission_serializes_each_owner_independently`.
- PERF-005: `HistoryService` commits pass the cached logical snapshot at the expected version (`commit_snapshot_known`); chunked commits compare unchanged pairs against it and decrypt only pairs it does not cover. A snapshot at any other version is ignored, so a stale copy cannot mask a change (store unit `known_snapshot_replaces_pair_decrypts_without_masking_changes`). `history_read_cost::committing_a_turn_decrypts_no_unchanged_pairs` red (`20261001T012136-f91016db47f1`) → green (`20261001T012314-b456446c454a`).

Full suite on the batch C+D tree: `20261001T012601-5c7fd5fd9bbc`, 1,087 passed, 0 failed (`temp/test-logs/phase5-batchD-full.log`); this is also batch C's clean gate.

## Batch PERF-E — voice first-audio (PERF-011, PERF-012, PERF-017)

- PERF-017 fixed: the GPU service's `/v1/stt` runs the injected converter (ffmpeg) and WAV staging via `asyncio.to_thread`, so a conversion no longer stalls other requests on the event loop. New `test_stt_conversion_does_not_block_other_requests`: red (`20261001T013711-1d2b58a88c50`, `/health` answered 3.00 s after a held conversion began) → green (`20261001T013939-a96d52ab7eca`, 65/65). `test_stt_thread_start_failure_removes_staging_file` now starts the loop's executor worker before patching `Thread.start`, so the injected failure still hits only the transcription job thread and its cleanup assertion is unchanged.
- PERF-011 rejected in part: the Kokoro streaming endpoint splits by sentence and the server already submits one sentence per request, so it would return one chunk; starting synthesis at `POST /tts` would bypass the GET-time destination/privacy revalidation that `voice_privacy` pins. Opus encoding inline on the runtime remains a measured-only lead: encode time per audio second needs the release build on the host.
- PERF-012 deferred: one-ahead desktop prefetch causes gaps only when synthesis latency exceeds clip duration, which requires GPU timing on the host; native already looks ahead four.

## Batch PERF-F — windowed page and pair reads (PERF-001 read path)

- PERF-001 read path fixed: `load_page` and `load_pair` go through `load_chunked_window`, which decrypts only the pairs in the requested range and returns the manifest from the same read transaction; `load_logical_chunked` delegates with the full range. New `a_history_page_decrypts_only_its_pairs` and `a_history_pair_decrypts_only_that_pair` in `history_read_cost.rs`: red (`20261001T014110-e289e9eea01f`, a one-pair page opened all 3 pairs) → green (`20261001T014236-b6dee07320d8`, 8/8). Out-of-range and `usize::MAX` pair indexes clamp to an empty window and still return `InvalidInput`; page bounds, `has_more` and `history_total` are unchanged. Regression jobs (worker-run, all green): `history_robustness` 21/21 (`20261001T015308-9dc3863b7ead`), core `--lib history` 88/88 (`…015400-5437d0835f91`), `load_set_history` 4/4, `conversation_state` 12/12, `activity_sync` 2/2, `prompt_input_boundary` 7/7, `history_snapshot_boundary` 7/7, `chat_service_lazy_history` 3/3, `history_cache_key` 1/1, `chat_service_test_chunks_isolation` 6/6.
