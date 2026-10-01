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
