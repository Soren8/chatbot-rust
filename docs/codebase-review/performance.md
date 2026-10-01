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

## Session 085 — Android inventory (N01–N03, leads)

Every production file in N01–N03 read 1→EOF (6,915 lines, worker read, primary-reviewed). Leads, with the measurement each needs:

| Lead | Location | Cost | Disposition |
|---|---|---|---|
| N-PERF-1 | `NativeMicPlugin.java:238–262, 793–809` | Per 20 ms frame: new buffer, main-looper post, JSObject, ~856-char Base64, `evaluateJavascript`; JS decodes again. 50 wakeups/s for the whole session, also while JS drops frames. | Batch PERF-G (measured fixture or recorded design). |
| N-PERF-2 | `NativeMicPlugin.java:200, 239, 243` | `getMinBufferSize` bytes used as a sample count: reads block for twice the intended time, frames arrive in bursts. | Batch PERF-G. |
| N-PERF-3 | `NativeMicPlugin.java:242–246` | `read <= 0` → `continue` with no backoff; error codes spin a core. | Batch PERF-G. |
| N-PERF-4 | `car/VoiceScreen.java:230–235` | The same spin plus a file log per iteration; recorder released on main while read. | Batch PERF-H. |
| N-PERF-5 | `VoiceScreen.java:296–313, 342–363, 439–463` | Car turn: GET `/`, `/get_sets` twice, `/stt`, `/chat` serially. | Deferred: car protocol/transport repair is user-deferred. |
| N-PERF-6 | `VoiceScreen.java:313–322, 484–537` | Car TTS waits for the saved generation and synthesizes the whole reply at once. | Deferred with N-PERF-5. |
| N-PERF-7 | `VoiceScreen.java:553, 607–611` | Drain sleeps for total duration, ignoring audio already played through blocking writes (up to ~8 s mic-deaf). | Batch PERF-H. |
| N-PERF-8 | `VoiceScreen.java:60, 274–298` | Utterances (≤ ~480 KB) queue without bound while a turn runs. | Batch PERF-H. |
| N-PERF-9 | `car/DurableVoiceProtocol.java:77–84` | `openTts` loops with no backoff when the stream opens to 404. | Batch PERF-H. |
| N-PERF-10 | `audio/OggOpusStreamDecoder.java:98–138, 209, 228–231, 306–307` | Uncompacted staging copied per feed and page; per-packet PCM arrays; per-sample synchronized writes. | Batch PERF-I. |
| N-PERF-11 | `audio/TtsBodyInputStream.java:17–47` | Cancelled watchdog tasks stay queued 15 s; queue depth equals recent reads. | Batch PERF-I. |
| N-PERF-12 | `NativeVoiceTtsPlugin.java:270–399` | 3–4 PCM copies per clip. | Retained: bounded by per-sentence clips the server muxes whole. |
| N-PERF-13 | `NativeVoiceTtsPlugin.java:54, 197–225` | Worker polls every 100 ms while waiting. | Retained: 10 wakeups/s only during active TTS sessions. |
| N-PERF-14 | `VoiceModeForegroundService.java:32–47, 221–273` | 15 s keep-alive resumes the renderer; untimed partial wake lock. | Retained: keep-alive is the designed background-voice contract; renderer cost is device-only. |
| N-PERF-15 | `util/FileLogger.java:50–90` | Formatter allocated per line; synchronous open/append/close; no size cap. | Batch PERF-I. |
| N-PERF-16 | `VoiceScreen.java:60–61, 718–744` | Two executors never shut down per Auto session. | Batch PERF-H. |
| N-PERF-17 | `VoiceModeSessionCoordinator.java:332–354` | Lock-screen Stop joins TTS/mic threads on main (≤ ~2 s). | Retained: rare user action; real durations device-only. |

N01 files (activity, secure key, logger plugin, util except `FileLogger`) and the remaining audio state machines carry no lead: per-session or per-action work only.

## Session 085 — server in-memory stores (leads)

| Lead | Location | Cost | Disposition |
|---|---|---|---|
| R-PERF-1 | `generations.rs` receipts, `idempotency.rs` `SttReceipts`, `tts/store.rs` admissions | 24 h retention, no per-owner cap; full `retain` sweep per replay under one mutex. Stale-version `/chat` records receipts without a provider call. | Batch PERF-J. |
| R-PERF-2 | `session_identity.rs:92–97, 220–240`; `request_context.rs:113–115`; `rate_limit_middleware.rs:18–28` | Every session lookup sweeps all sessions; cookieless lookups mint orphaned records; `/activity` unlimited. | Batch PERF-K. |
| R-PERF-3 | `history/cache.rs:20–21, 67–89, 190–219` | Entry-count cap over decrypted snapshots; expired entries resident; every hit deep-clones. | Batch PERF-L. |
| R-PERF-4 | `generations.rs:139–145, 330, 504` | Concurrency capped per (owner, set), not per owner; buffer budget counts text only (~5.5 MiB real ceiling per generation). | Retained as a policy choice; per-owner concurrency is a product decision. |
| R-PERF-5 | `connection_receipts.rs:19–35` | Each write decrypts the writer's rows to expire them; other owners' expired rows linger. | Rejected: allowlisted, rare writers, bounded at 24 h. |

- PERF-008 rejected: per-chunk events are a constant factor capped at 8,192 events / 4 MiB per generation, and the client's `seq` gap check is per line, so coalescing changes the protocol for no measurable gain.
- PERF-009 split: the receipt sweep folds into R-PERF-1; the user-store reopen is rejected — O(1) per request (four `exists`, two verifier reads, one HMAC) on low-frequency endpoints (one long-lived events stream, status on EOF, activity on recover).
- Weak lock maps (`generations.rs` admission, `idempotency.rs` in-flight, `set_privacy_coordinator.rs`) prune dead entries on every acquire. TTS token store is capped at 128 with a 10-minute TTL.
- Correctness note for a later pass (not performance): a retried `/chat` whose generation was removed more than 120 s after settling gets 404 instead of its recorded descriptor (`generations.rs:326`).

## Batch PERF-H — Android Auto failure bounds (N-PERF-4, 7, 8, 9, 16)

- New pure `car/CarVoicePolicy.java` (capture-read classification, one-in-flight/one-pending turn slot, buffer-bounded drain) runs under `javac` in `car_voice_failure_modes`; `VoiceScreen.java` wiring is source-pinned there because the car library has no stubs. Negative reads stop capture through a local recorder reference; empty reads sleep one frame with rate-limited logging; the drain waits only for `min(bytes written, track buffer)`; screen destroy clears pending main callbacks, stops capture and shuts down both executors (`shutdown`, so the queued explicit Stop still runs). A turn slot drops the pending utterance once capture has stopped; capture never restarts on the same screen.
- `DurableVoiceProtocol.openTts` renews an expired stream at most `MAX_TTS_OPENS = 3` times with the admission backoff, then takes the existing no-TTS path.
- Red: `20261001T020010-28ee8bace8db` (unbounded renewal), `20261001T020304-4adaa0c20b43` (policy missing, 2/2 failed). Green: `car_voice_failure_modes` 2/2 (`20261001T020700-5c2f969efad1`), `tts_download_queue` 3/3 (`…020834-a5bb409fe446`), `distribution` 21/21 (`…021041-3655935cf1ac`). `VoiceScreen.java` compiles only in the APK build gate.
- Noted, unchanged: `onDestroy` does not abandon audio focus; `retryAdmission` stays unbounded on `IOException` with backoff that stops with the session.

## Batch PERF-J — owner-capped receipt maps (R-PERF-1, PERF-009 sweep half)

- New `idempotency::OwnerReceipts<T>` backs the generation, STT and TTS-admission receipt maps: per-owner insertion-ordered queues capped at `MAX_RECEIPTS_PER_OWNER = 64`, expired and same-id receipts pruned on insert, lookups scan only the caller's queue, and idle owners are swept at most once per 60 s from insert. Replay results, the reuse 409 and 24 h expiry are unchanged for retained receipts; TTS replay now takes a read lock. Per-kind retention was not shortened: expired TTS tokens and post-deadline generations already replay as absent, and rejected/STT receipts would change client-visible replays.
- Tests `*_receipts_are_capped_per_owner_without_touching_other_owners` in `generations.rs`, `idempotency.rs`, `tts/store.rs` (10,000 ids for one owner; other owner kept; latest replays): red `20261001T020056-674a4434d2b6` (3 failed) → green `20261001T020454-8be794c67245`. Regression: server `--lib` 88/88 (`…020753-b002344f58ff`), `agent_connection_receipts` 3/3, `history_mutation_resend` 5/5, `operation_receipt_transport` 4/4, `server_owned_generations` 11/11, `stt` 7/7, `tts` 16/16 (`…022110-8649ca3f6f78`).

## Batch PERF-M — activity stream line parsing (PERF-016)

- `activity-sync.js` scans a chunk's lines by offset and slices the buffer once per chunk; the 20 s stall timer re-arms once per run of lines between awaits (again after each `reconcile`). A chunk without a complete line still does not re-arm. Fixture scenarios in `activity_sync_test.js`: 200 lines in one chunk (≤ 3 timer sets; was 201), a multi-byte line split across three chunks, and re-arm after `reconcile`. Red `20261001T020200-67359ab3505f` → green `20261001T020549-7c76bd28eac3`. Regression: `conversation_request_application` 1/1, `generate_connection_recovery` 2/2, `tts_download_queue` 3/3, `js_syntax` 11/11 (`…022012-f970b14e45e7`).

## Batch PERF-G — native mic read sizing and read errors (N-PERF-2, N-PERF-3)

- New Android-free `NativeMic/NativeMicCapture.java` holds the capture loop: reads are sized `getMinBufferSize / 2` samples (the byte count had been used as a sample count, doubling each blocking read), frames stay 20 ms little-endian with the partial frame flushed, a zero read continues, and a negative read ends the loop and returns the error. `NativeMicPlugin` runs it and, for the current recording generation only, logs, reports `VOICE-ERROR` and calls `stopRecording()`; JS sees `isRecording` false through its existing restart path.
- `native_mic_capture.rs` (javac fixture plus plugin wiring pin): red `20261001T020207-ba4e49c58d58` (0/2: 1280-sample reads, 5 reads per error) → green `20261001T020645-fd814d742636`. Regression: `android_volume` 4/4, `js_syntax` 11/11, `native_vad_speech_like` 6/6, `voice_capture_boundary` 7/7, `voice_lifecycle` 8/8, `voice_mode_reliability` 51/51 (`…022105-9433d9ae979b`).
- N-PERF-1 not implemented: main-looper wakeups and `evaluateJavascript` cost need device timing. Ordered options recorded: skip encoding when `!hasListeners("nativeMicData")` (still one post per frame); a JS-driven `setDelivering` flag (API change); N-frame batching (cuts wakeups N×, adds (N−1)×20 ms before barge-in confirmation, must be re-proven against the noisy-speech barge-in tests).

## Batch PERF-K — session lookups without sweeps or orphan records (R-PERF-2)

- `session_identity.rs`: per-request `clean_expired` removed from home bootstrap, CSRF validation, `session_context`, login and logout; expired records read as absent on lookup (CSRF false, rate-limit identity falls back to `guest:{cookie}`, home bootstrap replaces the record and sets the cookie); the 300 s background purge remains the only sweep. `session_context` never stores a record: without a live cookie it returns an unstored guest context (the minted record's cookie had never been sent, so it was unreachable). Stored records are minted only where Set-Cookie follows (home/login/signup page loads, `finalize_login`, logout).
- Tests: 4 core unit tests (expired rejected without global sweep; live record resolves; bootstrap replaces expired; cookieless lookup persists nothing) and `http_session_store_growth.rs` (100 cookieless/unknown-cookie `GET /activity`: no Set-Cookie, store size unchanged). Red: server `20261001T020148-478d89a51449` (store grew 0 → 200), core `…020409-a8a6dba55430` (2/4). Green: core `…020744-d3d288e30887` 4/4, server `…020914-79ae862e3f10`. Regression: full chatbot-server package `20261001T021103-97af654c7c3c` (777 passed, 116 binaries), core `http_identity_isolation` 4/4, `http_identity_lazy_init` 1/1.
- `/activity` rate limiting not added: the middleware wraps only the `rate_limited` sub-router (signup, login, chat, tts, stt, client_logs, regenerate), and `/activity` sits with the unlimited generation reads; with orphan minting gone it no longer grows server state. The existing `"/generations"` entry in `LIMITED_PATHS` is inert for the same reason (Phase 6/7 cleanup lead).

## Batch PERF-L — shared, byte-budgeted history cache (R-PERF-3)

- `SetCache` stores and returns `Arc<LogicalSnapshot>`: a hit is a refcount bump, `put_snapshot` moves the snapshot in, and `commit()` borrows the cached snapshot. Callers that need ownership use `Arc::unwrap_or_clone`, copying only while the cache still holds it. Retained plaintext is bounded by an approximate 64 MiB byte budget (history text, memory, prompt, name, pair ids) in addition to the 256-entry cap, evicting least-recently-used entries other than the one just inserted; a set larger than the budget is not cached. Expired snapshots and summaries are pruned on every insert. No public signature changed.
- Tests in `cache.rs` (`hits_share_one_snapshot_allocation`, `byte_budget_bounds_retained_plaintext`, `expired_entry_is_dropped_on_next_insert`): red `20261001T015924-f91575622b9a` (API absent) → green `…020221-490727c22ce2`. Regression: core `--lib history` 91/91, `history_snapshot_boundary` 7/7, `chat_service_lazy_history` 3/3, `history_cache_key` 1/1, `chat_service_test_chunks_isolation` 6/6, `prompt_input_boundary` 7/7; server `history_read_cost` 8/8, `history_robustness` 21/21, `load_set_history` 4/4, `conversation_state` 12/12 (`…041901-3d555ce12384`).
- Accepted limits: sizes are approximate (no allocator slack); relaxed counters can overshoot briefly under concurrent inserts until the next eviction; summaries stay entry-capped (metadata only).

## Batch PERF-I — native TTS decode, watchdog and file log (N-PERF-10, 11, 15)

- `OggOpusStreamDecoder`: staging is a growable array compacted on each feed and pages are parsed in place (no whole-stream `toByteArray` per feed and page, no per-page body copy); one decode buffer and one PCM scratch buffer are reused, written with one bulk `write` per packet; `FirDownsampler.process` fills a byte array. Output bytes are unchanged.
- `TtsBodyInputStream`: the watchdog is a `ScheduledThreadPoolExecutor` with `setRemoveOnCancelPolicy(true)`, so each read's cancelled alarm leaves the queue at once. The per-clip watchdog thread is retained.
- `FileLogger`: one formatter reused under the existing lock; the file rolls to a single `.1` backup at 1 MiB (~2 MiB on disk). No app code reads the file; the in-memory ring used by `ClientLogReporter` is unchanged. Open/append/close per line is retained.
- `audio_perf.rs` (watchdog queue ≤ 1 after 5,000 reads; real decoder compiled against a deterministic concentus stub, byte-identical to independent 48 kHz and 24 kHz references at whole/2 KB/1 B/7 B chunking, retained buffers ≤ 128 KB for a 2.5 MB stream) and `file_logger_cap.rs` (4 threads, ~7.4 MB logged; directory under 4 MiB; every line timestamp-valid). Red: `20261001T020812-c4cc0302f0c0` (queue 5,001; decoder retained 4.2 MB), `…020638-2a5f9e028cd9` (log 7.5 MB). Green: `…021032-f914b8ecbdfe` 2/2, `…021959-5e8cd49a9dfc` 1/1. Regression: `tts_download_queue` 3/3, `voice_mode_reliability` 51/51, `client_log_reporting` 2/2, `native_tts_communication` 2/2, `native_foreground_stop` 1/1, `distribution` 21/21 (`…041919-0ef822b56b69`).

## Session 085 — browser and GPU inventory (W01–W05, G01)

Every `static/*.js` module, the templates, both stylesheets and `chatbot-cuda/src/*` read 1→EOF (`chat.js` 5,074 lines; `chat.html` body with long lines truncated). Leads beyond PERF-013–016:

| Lead | Location | Cost | Disposition |
|---|---|---|---|
| B-PERF-1 | `chat.js:3811–3840, 2460–2489`; `playback-source.js:21–87`; `tts-playback.js` notify paths; `voice-text.js:198–328` | Per delta: full `data-original` rewrite, `publish`, and ~2 full speakable projections (~40 regex passes each) while a TTS queue is subscribed; O(K·L) per reply. | Batch PERF-N. |
| B-PERF-2 | `chat.js:327–331`; `activity-sync.js:249–263`; `session-client.js:140–183`; `login.rs:410–420` | Every focus/resume: GET `/login`, POST `/login/remember` (rotates the durable token), GET `/activity`, POST `/load_set` for a version. | Batch PERF-O. |
| B-PERF-3 | `chat.js:294–313` | Recovered/reattached events re-render full Markdown per event (≤ 8,192 on reattach). | Batch PERF-N. |
| B-PERF-4 | `chat.js:3883–3887, 2524–2528, 1018–1038` | Per reader chunk: layout read plus scroll write and two rAF callbacks. | Batch PERF-N. |
| B-PERF-5 | `chat-renderer.js:279–317` | Every frame re-highlights every fence (unknown languages through `highlightAuto`); two `console.debug` per block per render. | Batch PERF-P. |
| B-PERF-6 | `chat.html:261–305`; `chat.js:4173`; `lib.rs:185–207`; no compression layer | `ort.min.js` (358 KB) and the VAD bundle load synchronously on every chat page; ~1.5 MB uncompressed JS/CSS revalidated per load. | Open: lazy loading touches the `chat.js` gate (after PERF-N); compression depends on the host proxy, which this sandbox cannot see. |
| B-PERF-7 | `voice-capture.js:111–206`; `native-audio.js:128–189` | Pitch autocorrelation (~250k MAC) per speech-like frame when barge-in cannot fire. | Batch PERF-P, only with barge-in proof. |
| B-PERF-8 | `service.py:387–445`; native lookahead 4 | Up to five concurrent GPU inferences per turn, unordered; first sentence competes with lookahead. | Deferred: needs host GPU timing. |
| B-PERF-9 | `service.py:174–198` | STT compiled with `torch.compile` but never warmed; first request pays compile. | Batch PERF-Q. |
| B-PERF-10 | `audio_utils.py:188–219`; `main.py:144–170` | Two WAV copies and a process spawn per utterance. | Retained: host-only cost, expected < 20 ms. |
| B-PERF-11 | `chat.js:3879, 2520, 3570, 3619` | `/get_sets` plus option rebuild after every turn. | Retained: picks up server-side rename and version. |
| B-PERF-12 | `chat.js:1494–1508, 945–963` | Replace-mode set load mounts up to 80 bubbles into the live DOM with a layout read each. | Batch PERF-N. |
| B-PERF-13 | `chat.js:1437–1455, 2891–2904` | All thumbnails fetched at once. | Retained: small, immutable-cached. |
| B-PERF-14 | `style.css:18–40` | Infinite pulse animation for the whole voice-mode session. | Retained: visual product choice; compositor cost is device-only. |
| B-PERF-15 | `enc-key.js:62–74, 210–230, 522` | Three IndexedDB opens (never closed) and two readwrite deletes per page load. | Batch PERF-Q. |

No lead in `login.js`, `tt.js`, `native-bridge.js`, login/signup templates, `opencode-theme.css`, `conversation-state.js`, `voice-lifecycle.js`, `voice-events.js`, `stream-decoder.js`, `credential-crypto.js`, `credential-metadata.js`, `agent-connections.js`, `settings.py`. Desktop hover highlight, the scroll-time hover clear and the settings resize handler are rAF-coalesced or trivial. Correctness note for a later pass: concurrent tabs rotating the shared remember cookie on focus may race.

## Session 085 — remaining server and core inventory

C01, C03, C05, C07, C08, P01, S02, S03, S04, S06, S08, S09, S11, S12 and R01 read 1→EOF (14,544 lines; `openai.rs` and `tts/text.rs` test modules scanned by name). Leads:

| Lead | Location | Cost | Disposition |
|---|---|---|---|
| S-PERF-1 | `generation_deps.rs:273–293`; `providers/openai.rs:81–86`, `xai.rs:65–70`, `generation.rs:186` | A new `reqwest::Client` per `/chat` and `/regenerate` turn: no connection pool, so DNS + TCP + TLS before every first token. | Batch PERF-R. |
| S-PERF-2 | `set_privacy_coordinator.rs:62–66` (from `chat.rs`, `regenerate.rs`, `stt.rs`, `tts.rs`) | Set membership via `list_sets`: one policy open per user set on every turn and every spoken sentence. | Batch PERF-S. |
| S-PERF-3 | `rate_limit_middleware.rs:18–28`; `lib.rs:373–377` | `/tts`, `/tts_stream/{token}` and cancel each spend the per-user budget, so short-sentence replies can hit 429 mid-playback. | Batch PERF-T (budget size untouched). |
| S-PERF-4 | `login.rs:116–135`; `signup.rs:147` | bcrypt and PBKDF2 run inline on a runtime worker. | Batch PERF-T. |
| S-PERF-5 | `user_store.rs:479–532` | Whole `users.json` parsed per call; rewritten with fsync per preference save. | Retained at household scale; mtime-keyed cache if users grow. |
| S-PERF-6 | `sets.rs:922–936`; `api.rs:431` | Rename/delete and name-only lookups materialize every image to read metadata. | Batch PERF-S. |
| S-PERF-7 | `lib.rs:387–431`; `tower-http` without compression | No response compression or precompressed static files. | Open: depends on whether the host reverse proxy compresses (not visible from the sandbox). NDJSON events must stay uncompressed for per-event flushing. |
| S-PERF-8 | `lib.rs:387–388` | Cross-origin isolation layer is applied before any route, so COOP/COEP are likely never sent and threaded ORT stays single-threaded. | Open for the user: enabling COEP `require-corp` changes every subresource load. |
| S-PERF-9 | `openai.rs:566–591`; `xai.rs:246–269` | Per SSE line, the buffer remainder is moved; quadratic only within one large read. | Retained: bounded by read size. |
| S-PERF-10 | `generation.rs:148–204`; `search.rs:160–161` | Search turns clone the payload about three times, including an eager fallback stream. | Batch PERF-R if small, else retained. |
| S-PERF-11 | `remember_store.rs:242–330` | Remember issue scans every family file twice. | Retained: login-rate only, capped families, background purge. |
| S-PERF-12 | `identity.rs:187–197` | `/client_logs` runs a full session sweep per POST (PERF-K residual). | Batch PERF-T. |

No lead in config/logging, persistence/legacy migration (one-time), rate limiter, names/Fernet, core agent connectivity, TTS text normalization, TTS backend (shared client), server agent connections (allowlisted, ≤ 16 records). Correctness findings for a later pass (not performance): split multi-byte UTF-8 across SSE reads becomes U+FFFD (`openai.rs:283, 405`; `xai.rs:191`); `search.rs:220` byte-slices a result and can panic on a non-char boundary; `user_store.rs:182–209, 414–451` read-modify-write `users.json` without a lock, so concurrent signup and preference saves can lose writes.

## Batch PERF-Q — IndexedDB connection reuse and STT warmup (B-PERF-15, B-PERF-9)

- `enc-key.js` keeps one lazily opened IndexedDB connection per page (cached promise, dropped on failed open, `close` or `versionchange`, closing on `versionchange`). The load-time scrub reads all entries and writes only when a wrap key, legacy wrapped slot or wrapped non-PRF slot exists, applying deletes and rewrites in one readwrite transaction; resulting records are unchanged.
- `InferenceService.load_models` transcribes one second of silent mono 16-bit WAV through the request path after loading STT, so the first `/v1/stt` no longer pays `torch.compile`; warmup failure warns and startup continues.
- Tests: `enc_key_idb_test.js` via `credential_metadata` (one connection across operations, reopen after close/versionchange, no write on a clean load, same scrub results on a dirty one) and `test_service.py` warmup cases (input, temp-file cleanup, non-fatal failure) through `voice_service_lifecycle`. No red job was recorded: the batch was resumed from a stopped worker whose partial fix was already in the tree. Green: `credential_metadata` 7/7 (`20261001T050319-65a86bb77945`), `voice_service_lifecycle` 1/1 with Python 67/67 (`…045831-59886d18a432`), `js_syntax` 11/11 (`…050547-63ff7bff65e6`).

## Batch PERF-P — fence highlighting and idle pitch analysis (B-PERF-5, B-PERF-7)

- `chat-renderer.js` caches highlighted output per language and decoded code (reset when the highlighter instance changes, and after 64 entries so a streaming open fence does not retain every prefix); a closed fence is highlighted once instead of every frame. The two per-block `console.debug` calls are gone. Output is unchanged.
- `voice-capture.js` runs the pitch autocorrelation (start-window scan and rolling voiced window) only while a voice session is active and barge-in has not fired; `voicedMs` feeds only the barge-in check. Voiced time now accrues from session start, so speech that began before TTS started no longer counts toward barge-in.
- Red `20261001T045424-a88175413477` (30 `highlightAuto` calls) → green `chat_renderer_boundary` 3/3 (`…050950-20c84a1f1f1d`, with the cache cap). Fixture `voice_capture_test.js` pins no voicing work while idle, unchanged confirm timing while armed and none after firing. Regression: `voice_capture_boundary` 7/7 (`…045931-2264c807a85c`), `voice_mode_reliability` 51/51 (`…050222-bac469d3f160`), `native_vad_speech_like` 6/6 (`…050424-4e96ca751c48`), `js_syntax` 11/11 (`…050651-814ffd64ff11`).

## Batch PERF-N — streaming client cost (B-PERF-1, 3, 4, 12)

- `chat.js` chat and regenerate streams mark `data-original` dirty per chunk; the frame renderer writes it, publishes to the playback source, renders and pins to the bottom once per frame (one stick sample per frame instead of per reader chunk). Done and error paths flush first, and a hidden page flushes per chunk because it gets no animation frames, so background voice playback still receives text. `playback-source.js` caches the speakable projection until the published text changes, so TTS queue reads stop re-projecting the whole reply (`tts-playback.js` and `voice-text.js` unchanged).
- Recovered/reattached activity paints once per frame; `error` and `saved` paint immediately, and a switch of generation or an interruption flushes the pending paint. Replace-mode set loads build bubbles in a fragment and mount once with one stick sample.
- Fixtures `conversation_request_application_test.js` (counter bounds plus final DOM text parity) and `playback_source_characterization_test.js` (projection cached, same sentences). No red job: the stopped worker's partial fix was already in the tree and first runs passed; review added the missing visible-chunk dirty flag and the hidden-page flush. Green: `conversation_request_application` 1/1 (`20261001T051144-66f674e697ff`), `playback_source_characterization` 10/10 (`…050403-d74564d24296`), `js_syntax` 11/11 (`…051204-417ba83d053e`).

## Batch PERF-R — shared provider HTTP client (S-PERF-1)

- `providers::shared_client` keeps one `reqwest::Client` per request timeout (the builder's only input) for the process; OpenAI and xAI providers take it instead of building a client per turn, so `/chat` and `/regenerate` reuse pooled connections. Timeouts are unchanged; the old builders set no headers.
- `llm_client_reuse.rs` (two real `/chat` turns against a keep-alive upstream): red `20261001T045920-5dde8087e8cf` (2 connections) → green `…050305-6040291c2b38` (1). Regression: server `--lib` 88/88 (`…050503-da53aaeb0f3b`), `chat` 2/2, `regenerate` 3/3, `generation_dispatch` 15/15 (`…051007-9b5d9507c9aa`).
- S-PERF-10 (search-turn payload clones in `providers/generation.rs`) not attempted; retained.

## Batch PERF-T — auth hashing, log sweeps and stream budget (S-PERF-3, 4, 12)

- Login runs bcrypt verify, PBKDF2 derivation and the key-verifier write in one `spawn_blocking`; signup runs its bcrypt hash there. Responses and error mapping are unchanged. `auth_hash_offload.rs` 2/2 (`20261001T045749-3b3ee1e8be48`).
- `RequestIdentity::has_live_session` (used by `/client_logs`) no longer purges the session store; the rate-limit identity is already expiry-aware. `client_logs_session_sweep` 1/1 (`…050041-4e937e4cb681`), `http_session_store_growth` 1/1 (`…051107-254d34bc7f57`).
- `/tts_stream/{token}` GET and DELETE leave the rate-limited path list (the token is the bearer credential); `/tts` admission still counts and the budget is unchanged. `tts_stream_rate_budget`: red `…045412-8240986a994c` (429 at the 20th request) → green `…045646-8a0c3070cb8a`.
- No red for the hashing and sweep halves: the stopped worker's fixes were already in the tree. Regression: `login` 8/8, `signup` 2/2, `credential_metadata` 7/7, `rate_limit` 2/2 (`…050957-c9644811d4f8`).

## Batch PERF-S — set resolution from metadata (S-PERF-2, S-PERF-6)

- `resolve_content_set` (chat, regenerate, STT, TTS) checks an explicit set id against its plaintext meta row (`HistoryService::ensure_owned`) and resolves a name through `find_summary_by_display_name`, which reads name rows and opens one policy for the match; the default set resolves through `ensure_default_set_id`. A missing set is still `NotFound`.
- `sets.rs` rename/delete resolution and `ChatService` mutation mirrors use `set_summary` / `find_summary_by_display_name` instead of materializing snapshots; `list_sets` shares the per-set `summary_of`, which opens history only to backfill a missing name row. A name match whose policy is foreign is skipped and the scan continues.
- `cost::take_policy_opens` counts sealed policy opens. `history_read_cost` adds bounded policy opens per turn and zero image opens for name-only lookups, rename and delete. No red job: the stopped worker's fix was already in the tree. Green: core `--lib history` 91/91 (`20261001T051349-f4d704cd3643`), `history_read_cost` 14/14 (`…051441-5451cec2f874`), `voice_privacy` 10/10 (`…051551-1459d62d5536`), `sets` 1/1 (`…051713-dd473351e720`), `history_robustness` 21/21, `load_set_history` 4/4, `conversation_state` 12/12 (`…051211-88475d235326`).
