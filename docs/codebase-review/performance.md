# Performance and resource-use review (Phase 5)

Scope: measured repository-wide performance review, prioritizing chat latency, client/mobile work, voice pipeline and unbounded RAM. Static observations remain leads unless measured; GPU/device/host-only costs are evidence limits.

## Findings

| ID | Location | Finding | Final disposition |
| --- | --- | --- | --- |
| PERF-001 | `chatbot-core` history reads and prepare | Whole-history materialization for page/pair reads and prepare. | Page/pair reads decrypt only their requested windows; prepare plans/truncates first and resolves only images in kept pairs. Full suite recorded green. |
| PERF-002, PERF-010 | Chat, STT and TTS privacy checks | Reading policy by materializing all images. | Fixed with policy-only reads under the content permit; measured image opens eliminated for these checks. |
| PERF-003, PERF-004 | Prompt image packing | Unneeded thumbnail work and repeated history clones. | Fixed: plan before image work, reuse stored thumbnails for kept pairs, and use one working copy. |
| PERF-005 | Chunked history commit | Appends decrypted every existing pair. | Fixed: version-matched cached logical snapshot avoids decrypting unchanged pairs. |
| PERF-006 | Generation event views | Repeated full-buffer scans/clones. | Fixed: sequence-based slicing returns only new events. |
| PERF-007 | Generation admission/Stop | One global lock serialized unrelated owners. | Fixed: per-owner admission locks; regression pins independent ownership. |
| PERF-008 | Durable generation event protocol | Per-provider-chunk NDJSON overhead. | Rejected: bounded at 8,192 events / 4 MiB per generation; coalescing changes protocol without measured gain. |
| PERF-009 | Receipt replay and user-store access | Replay sweeps receipts; request reopens store. | Split: receipt sweeps addressed by owner-capped receipts (PERF-J); O(1) store reopen retained for low-frequency endpoints. |
| PERF-011 | TTS synthesis/Opus path | Full-clip synthesis and inline encoding affect first audio. | Streaming endpoint rejected: Rust already requests one sentence at a time and early synthesis bypasses GET-time privacy revalidation. Inline Opus cost remains unmeasured pending host release-build timing. |
| PERF-012 | Desktop sentence playback | One-ahead prefetch may create gaps. | Deferred: requires GPU synthesis timing; native already looks ahead four. |
| PERF-013 | TTS sentence discovery | Re-splitting the full response each notification. | Fixed: incremental split from last queued sentence; spoken text unchanged. |
| PERF-014 | Desktop/native playback idle polling | Frequent polling despite source subscriptions. | Fixed: one-second fallback while subscriptions wake normal work; behavior retained without subscription. |
| PERF-015 | Streaming Markdown rendering | Full accumulated text reparsed/replaced for each delta. | Fixed: frame-coalesced rendering, terminal flushes and stale-request guard; WebView frame/battery effects remain device-only. |
| PERF-016 | `static/activity-sync.js` | Per-line timer churn and repeated remainder slicing. | Fixed: offset scanning, one slice per chunk and bounded timer re-arming; multibyte split behavior pinned. |
| PERF-017 | GPU service `/v1/stt` | Synchronous conversion blocked event loop. | Fixed: conversion and staging run via `asyncio.to_thread`; concurrent-request regression passed. |
| N-PERF-1 | `NativeMicPlugin.java` frame delivery | Main-looper posts, JS object/base64 and evaluation every frame. | Open: requires device timing; batching/API options must preserve barge-in latency and noisy-speech behavior. |
| N-PERF-2, N-PERF-3 | Native mic capture loop | Buffer byte count treated as samples; read errors could spin. | Fixed: 20 ms sample-sized reads, partial flush, zero-read continue, negative-read stop/error; JVM fixture passed. |
| N-PERF-4, N-PERF-7, N-PERF-8, N-PERF-9, N-PERF-16 | Android Auto `VoiceScreen`/protocol | Error spin, overlong drain, unbounded queued audio, renewal loop, executor lifetime. | Fixed: bounded turn slot/drain, backoff-limited TTS renewal, capture failure handling and executor shutdown; APK gate passed. |
| N-PERF-5, N-PERF-6 | Android Auto request/TTS flow | Serial car protocol and whole-reply TTS. | Deferred: car protocol/transport repair is user-deferred. |
| N-PERF-10, N-PERF-11, N-PERF-15 | Native Opus decoder, watchdog, file logger | Repeated copies, retained cancelled alarms, unbounded synchronous log file. | Fixed: reusable buffers/in-place parsing, remove-on-cancel scheduling, reused formatter and 1 MiB rolling file; byte/cap regressions passed. |
| N-PERF-12, N-PERF-13, N-PERF-14, N-PERF-17 | Native TTS copies/polling, foreground keep-alive and stop | Bounded copies/polling; designed keep-alive; rare stop join. | Retained: per-sentence clips bound copies, polling is limited to active TTS, keep-alive is product contract; stop timing is device-only. |
| R-PERF-1 | Generation/STT/TTS receipt maps | Uncapped 24-hour per-owner receipts and full sweeps. | Fixed: per-owner cap 64, caller-local lookup, expiry pruning and throttled idle-owner sweep; replay semantics for retained receipts unchanged. |
| R-PERF-2 | Session identity lookups | Per-request sweeps and cookieless orphan records. | Fixed: expiry-aware lookup, background-only purge and no stored cookieless context; growth regression passed. `/activity` rate limit not added. |
| R-PERF-3 | History cache | Entry-only cap, resident expired entries and deep-clone hits. | Fixed: shared `Arc` snapshots, approximate 64 MiB byte budget plus 256-entry cap and expired-entry pruning. Approximation/concurrent overshoot accepted. |
| R-PERF-4 | Generation concurrency/event buffers | Per-set concurrency and text-only buffer accounting. | Retained as policy choice; per-owner concurrency is a product decision. |
| R-PERF-5 | Connection receipts | Expiration reads decrypt other owners' rows. | Rejected: allowlisted, rare writers, 24-hour bound. |
| B-PERF-1, B-PERF-3, B-PERF-4, B-PERF-12 | Browser stream projection, reattach, scroll, replace loads | Repeated projections/rendering/layout and incremental DOM mounts. | Fixed: projection cache, frame-coalesced paints/scroll sampling, fragment mount; visible text parity pinned. |
| B-PERF-2 | Browser focus/resume | Unnecessary login/remember rotation on each resume. | Fixed: live session uses activity and set reconcile; expired session refreshes once on 401. |
| B-PERF-5, B-PERF-7 | Browser Markdown highlighting and pitch analysis | Re-highlighted fences and autocorrelation when barge-in cannot fire. | Fixed: bounded highlight cache and pitch work only while armed; barge-in timing pinned. |
| B-PERF-6 | Browser static assets / host proxy | Large synchronous assets and uncompressed responses. | Open: lazy loading depends on PERF-N/chat gate; compression depends on host-proxy behavior not visible in sandbox. |
| B-PERF-8 | GPU sentence lookahead | Concurrent inference can delay first sentence. | Deferred: requires host GPU timing. |
| B-PERF-9 | GPU STT startup | First request pays compile cost. | Fixed: startup warmup via request path; warmup failure is non-fatal. |
| B-PERF-10, B-PERF-11, B-PERF-13, B-PERF-14 | GPU WAV path, set refresh, thumbnails, voice pulse | Host-only WAV/spawn cost; required refresh; immutable-cached thumbnails; visual animation. | Retained: expected host cost under 20 ms; refresh preserves rename/version; thumbnails small/cacheable; pulse is product choice and compositor cost is device-only. |
| B-PERF-15 | Browser IndexedDB | Repeated database opens and writes on page load. | Fixed: one lazy connection per page; clean load avoids writes; close/versionchange reopens safely. |
| S-PERF-1 | OpenAI/xAI provider HTTP | New HTTP client per turn prevented connection reuse. | Fixed: shared clients keyed by timeout; keep-alive regression confirmed two connections reduced to one. |
| S-PERF-2, S-PERF-6 | Set policy/name resolution and mutations | Full set materialization to resolve metadata. | Fixed: metadata/summary resolution avoids image materialization; policy opens bounded to relevant sets. |
| S-PERF-3, S-PERF-4, S-PERF-12 | TTS budgets, password hashing, client-log session sweeps | Playback requests consumed budget; CPU hashing ran inline; log POST swept sessions. | Fixed: only TTS admission counts, hashing uses `spawn_blocking`, live-session check avoids purge sweep. |
| S-PERF-5, S-PERF-8, S-PERF-9, S-PERF-11 | User-store writes, COEP, SSE buffer, remember scans | Household-scale file store; user-impacting COEP; bounded line parse; login-rate scan. | Retained/open: user store retained at household scale; COEP requires user decision because it affects every subresource; SSE cost bounded by read size; remember scan is login-rate and family-capped. |
| S-PERF-7 | Rust responses/static assets | No compression layer. | Open: depends on host reverse proxy; NDJSON must preserve per-event flushing. |
| S-PERF-10 | Search provider payload | Search path clones payload repeatedly. | Retained; not attempted in PERF-R. |

## Cross-pass items

SSE parsing moves buffer remainders; cost is quadratic only within one bounded read, so it is retained. Splitting multi-byte UTF-8 across reads remains a correctness lead, not a performance finding.

- MOD-005 projection/clone verification is recorded in [modularity.md](modularity.md).
- The timing-dependent GPU shutdown failure observed during PERF-C belongs to [test-quality.md](test-quality.md); two immediate reruns passed.
- Cross-pass open findings and owners are listed in [findings.md](findings.md).

## Decisions

- Static inspection is a lead, not a remediable finding; require deterministic cost evidence where the environment permits.
- Keep product/protocol and correctness behavior unchanged unless a measured bound justifies a change and regression coverage pins it.
- Preserve per-event NDJSON flushing, privacy revalidation, desktop/native barge-in semantics and documented background-voice behavior.
- Mark host, GPU and device-only costs as evidence limits rather than infer measurements.

## Open items

- B-PERF-6 waits on the `chat.js` gate/lazy-load follow-up and host-proxy compression behavior; compression must preserve NDJSON event flushing.
- S-PERF-7 waits on whether the host reverse proxy compresses responses.
- S-PERF-8 waits on a product decision about enabling COEP `require-corp` across all subresources.
- PERF-011 inline Opus encoding and PERF-012 prefetch gaps wait on host release-build/GPU measurements.
- N-PERF-1 main-looper delivery waits on device timing and a barge-in-safe delivery contract; B-PERF-8 waits on host GPU timing.
- PERF-008 and S-PERF-10 remain rejected/retained as above; car protocol work remains user-deferred.

## Completion

Phase 5 completed on 2026-10-01 (session 085). Final gate at `5f64c9e`: full suite `20261001T052944-8b04233f9f0f` passed (146 test binaries); APK `20261001T052703-f0fc4f8ed592` built `chatbot-physical-debug.apk`. Applying Phase 5 needs a host rebuild/restart of the server and static assets, the GPU voice service and the Android app.
