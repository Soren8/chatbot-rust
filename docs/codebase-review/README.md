# Codebase review program

Latest resume point: [session 009 — encryption-key cookie boundary](#session-009--encryption-key-cookie-boundary-2026-09-17). Earlier checkpoints record their original scope and status.

## Overall phase status and review gate

Phase 1 of seven is modularity: the initial whole-codebase assessment is complete, and bounded remediation remains in progress. Phases 2–7 (simplicity, abstractions/reuse, security/privacy, performance, test quality, documentation) have not started. The user authorized continued phase-1 work and requested a main-model read-only review after phase-1 remediation, before phase 2. That review is still pending; individual passing batches do not mark phase 1 complete.

Seven remediation batches have landed through session 009. Verified boundaries include live naming/Fernet helpers, browser stream decoding, TTS text/backend/token-store ownership, shared generation dispatch/message ownership, and encryption-key cookie transport. Remaining structural work includes typed core outcomes, session/chat separation, generation lease ownership, application-service composition, history API boundaries, broader request context, browser/native voice coordination, credential-cache interfaces, voice-service lifetimes and distribution settings. Auto support requires a contract decision. Partial findings and compatibility decisions must receive explicit dispositions before the phase-completion review; cross-pass security/correctness leads remain separately tracked.

## Purpose and authority

Review the entire repository across seven separate passes: modularity; simplicity; abstractions, reuse, and duplication; security and privacy; performance and resource use; test coverage and quality; documentation accuracy. The goal is evidence-backed improvements that preserve intended behavior, not a rewrite or a target number of findings.

The primary reviewer personally reads the implementation and relevant callers before defining remediation. Implementation workers may receive bounded fixes afterward; they do not perform the initial review, redelegate, or commit. Each worker has exclusive file ownership. The primary reviewer examines the resulting diff and integration behavior before accepting it.

Complete a pass, consolidate related findings, and agree on a bounded remediation batch before proceeding to the next pass. A confirmed serious security or data-loss issue may interrupt this sequence. Incidental observations from later passes are recorded without claiming those passes are complete.

## Records

- [Coverage](coverage.md) assigns tracked paths to review units and records independent progress for every pass.
- [Findings](findings.md) records evidence, uncertainty, disposition, correction proposals, and verification requirements.
- [Boundary map](boundaries.md) records observed dependencies and flow-tracing progress. It describes implementation evidence separately from intended architecture.
- [Modularity report](modularity.md) contains the completed first architectural pass, MOD-003–017, cross-pass leads, and remediation ordering.

The baseline is commit `4cda3039d3e5a58932a3c40afccc1e4ce33a19e3`. Line references refer to that revision unless explicitly superseded. Review records are version-controlled; temporary notes are not required to resume. Review findings are observations, not new application guarantees or approved implementation designs.

## Review method

Read each unit in context, including callers, state ownership, failure paths, and relevant tests. Trace cross-component flows as well as individual files. File size, repetition, and search results are leads, not sufficient evidence of a defect. Record useful existing boundaries as well as problems.

Each finding receives a stable category ID, priority, confidence, affected paths/symbols, evidence, consequences, proposed correction, invariants, verification needs, dependencies, and disposition. Use dispositions `needs investigation`, `confirmed`, `approved`, `in progress`, `verified`, `deferred`, or `rejected`. Preserve rejected and resolved findings with their rationale. A verified fix includes its commit and actual verification evidence.

Priorities describe impact: P0 urgent security/data-loss or operational emergency; P1 substantial correctness/security/reliability risk; P2 meaningful maintainability or efficiency problem; P3 minor improvement. Do not infer exploitability from a suspicious pattern or claim a performance bottleneck without suitable evidence.

### Testing standards and authorization

Favor broad behavior-focused unit coverage at the smallest practical level, with integration and end-to-end tests for risks that require those boundaries. A regression test may belong at any level. Coverage measurements locate gaps; they do not substitute for meaningful assertions.

Assess readability, diagnostic failures, proportional fixture/mock complexity, isolation, determinism, concurrency, behavioral coverage, brittleness, and redundancy. Check both coverage gained and coverage lost by proposed changes. Tests that only pin source spelling or repeat implementation logic require scrutiny, not automatic deletion.

For this explicitly authorized test-improvement work, the user permits modifying, consolidating, replacing, or removing tests when the review justifies it. The prohibition against changing tests to make broken application code pass still applies. Establish the intended contract before altering disputed expectations. Application bug fixes first require a failing regression; preserve that regression while fixing the implementation. Refactors require adequate passing behavioral coverage before restructuring.

Run application integration tests through `testctl --project chatbot-rust --suite test --repo /workspace/chatbot-rust`, using the supported container suite. Retain logs under `temp/test-logs/`. A green full run is final for its change set; rerun only after a relevant change or failure. Validate provider configurations through the appropriate suite before application commits. Documentation-only review checkpoints use document/reference and diff checks; they do not imply application validation or require running an unchanged application suite.

### Documentation standards

Compare claims against current code, configuration definitions, tests, and build/deployment definitions. Distinguish implemented, partially implemented, planned, and unverified behavior explicitly. Review defaults, commands, examples, paths, architecture, privacy/security guarantees, and contradictions between documents. Update relevant documentation with accepted fixes; reconcile the whole repository again in the documentation pass.

### Session continuity

At session start, inspect the working tree and changes since the recorded revision. Assign new paths to units and mark affected previously reviewed cells stale, including dependent flows where appropriate. Do not silently treat coverage at an old revision as current. At session end, record precise read boundaries, unresolved questions, decisions, verification, and the next entry point. Make a local commit for the checkpoint; do not push.

## Initial checkpoint — session 001, 2026-09-16

Established the seven-pass inventory and reviewed the Rust workspace dependency direction, server startup/router composition, middleware definitions, and HTTP error adapter. Supporting reads followed the home handler, test-workspace construction, and selected core session/config/history boundaries. No full application flow has yet been traced end to end.

The composition unit's modularity review is complete within its stated scope. Core sessions and shared test support remain partial. Two structural findings are confirmed; three cross-pass leads need investigation. No finding has been approved for implementation. No workers were used, and no application code, tests, or operational configuration changed.

Verification: checked inventory assignment against tracked paths, document references, baseline evidence, and `git diff --check`. The application suite was not run for this documentation-only checkpoint. No current application-test result is claimed.

**Next entry point:** continue modularity unit C02 in `chatbot-core/src/session.rs`: read lines 740–759 and 1058–1796, then trace consumers in `chatbot-server/src/chat_utils.rs`, `chat.rs` (remaining lines 231–452), `regenerate.rs`, and relevant state-mutating routes. Consult `docs/design-history-store.md` and `docs/design-history-chunks.md` before evaluating durable-state ownership. Review the existing behavioral tests before proposing any split. Resolve the scope of MOD-001/MOD-002 without broadening into a blanket dependency-injection rewrite.

## Current checkpoint — session 002, 2026-09-16

**The first modularity pass is complete at the application-architecture level.** Direct review covered all handwritten Rust production implementation, all first-party browser JS/templates/styles, all 20 Android production Java files, the Python voice service, all server integration-test files and executable fixtures, all Android tests, shared test support, and deployment/CI/build boundaries. Inline Rust tests were examined selectively for dependencies/setup; their complete assertion audit belongs to pass six. Generated/vendor/protected materials have explicit boundary-only dispositions. See coverage for exact limits; this is not a claim of 100% test coverage or an exhaustive security audit.

Seventeen structural findings are recorded (MOD-001–017). The central recommendation is clearer ownership inside the existing architecture: owned application services; identity versus chat orchestration; typed errors and generation leases; provider dispatch; logical history versus client projections; browser conversation state versus DOM; voice session/resource coordination. Existing crate/process boundaries, private redb internals, codec/queue helpers and shared browser product behavior should be retained.

The review also found cross-pass issues that deserve early reproduction: native plugin key export (SEC-003), log authorization using unverified rate-limit identity (SEC-002), concurrent user-store lost updates (COR-001), and contradictory native/JS TTS exhaustion contracts (COR-002). These are separately tracked so behavior fixes do not disappear into structural refactors. No production or test files were modified, and no workers were used for the review.

Verification for this documentation-only review consists of tracked-path assignment, finding-ID/link/reference checks, source-boundary checks, and diff/whitespace review. The application suite, GPU service, APK, browser automation and on-device tests were not run. Previously green application commits are not evidence that these new observations have been reproduced.

**Next working session:** inspect changes since `7dc8a23`, read the report's remediation ordering, and select a bounded first remediation batch. Prioritize regression-backed verification of SEC-003/SEC-002/COR-001 over cosmetic moves. For structural work, begin with stable behavioral test seams and shared stream decoding before splitting browser/voice ownership. Worker handoffs must include the finding, reviewed caller chain, invariant list and exclusive files; workers implement, the primary reviewer verifies. If choosing to postpone remediation, the next whole-codebase review is the simplicity pass, with fresh independent coverage.

## Session 003 — first remediation batch, 2026-09-16

The user authorized modularity remediation and preferred implementation subagents with primary review. This first bounded batch addresses MOD-004 and the speech-text boundary within MOD-011. Two workers had exclusive ownership after the primary reviewed the implementations and callers; the primary reviewed their diffs, narrowed the internal crypto module's visibility, and verified the TTS relocation against the original source. This is the first remediation batch, not completion of all seventeen findings.

**MOD-004 is verified:** `names.rs` owns username/set-name rules and typed errors; private `fernet_crypto.rs` owns Fernet operations. Session sealing, history crypto and HTTP naming paths no longer import migration-owned helpers/errors. Legacy wrappers retain their APIs, plaintext mode and error variants. Existing migration support and user-facing name/error behavior are preserved.

**MOD-011 is in progress:** `tts/text.rs` owns normalization with a single parent-visible entry point and all 28 existing normalization tests. The extraction preserves transformation order and output. Token state, backend synthesis and HTTP/codec rendering still share the parent module and require a later batch. Browser/native sentence policy was not part of this change.

Verification used the full supported command, `testctl --project chatbot-rust --suite test --repo /workspace/chatbot-rust`, twice for distinct states: the original implementation plus 16 new characterization tests passed in job `20260916T161549-8201e4a67090`; the refactored implementation passed in job `20260916T163326-652a9002d614` (both `status=passed`, exit 0). The final suite includes seven additional direct helper tests, legacy migration/idempotency/wrong-key coverage, provider configuration validation, session/history HTTP tests, TTS endpoint tests, and existing JS/Java queue regressions. Logs are `temp/test-logs/modularity-batch1-baseline.log` and `temp/test-logs/modularity-batch1-final.log`. No application source changed after the final passing run. No GPU, APK, device or live-deployment validation is claimed.

Implementation and this verification record belong to the local commit titled **“Extract live naming, Fernet, and speech text helpers”**, based on `9b2624b`. Rebuild/restart the webserver on the host to deploy that commit.

**Next entry point:** select the next bounded modularity batch. The shared stream decoder/test seams (MOD-010/016) remain the next browser foundation; finishing the TTS backend-result/HTTP boundary (MOD-011) is another independent slice. Larger session/service/voice ownership changes remain open. SEC-002/003 and COR-001/002 retain their separately recorded investigation requirements and were not reproduced or corrected in this structural batch. The six later whole-codebase passes remain unstarted.

## Session 004 — shared stream decoder, 2026-09-16

The user authorized the second modularity batch for MOD-010 with the corresponding MOD-016 seam. The worker personally reviewed the three browser parsers, server encoders and existing wire/test coverage before choosing a bounded browser-side extraction that preserves the wire contract with explicit adapters and no silent fixes.

**MOD-010 browser extraction verified:** `static/stream-decoder.js` owns incremental decoding and whole-text projection, emitting visible/thinking segments in wire order as they are found. History delegates projection; regenerate pushes with console stripping disabled and drops the residual at EOF; chat pushes with console stripping plus console logging and flushes at EOF/interrupt. Split console-detail across chunks is emitted, not retracted. Status labels, TTS selection and Rust think-stripping/normalization are unchanged callers; typed wire events remain separately approved.

**MOD-016 partial:** the new `stream_decoder.rs` plus `stream_decoder_test.js` require the shared unit directly with explicit literal expectations, including exact mixed visible/thinking callback order, and keep packaging/wiring pins to the real load-order/delegation contract. No existing tests were modified. Broader fixture/harness consolidation and the noted inconsistent voice contracts remain for pass six.

Review correction: the first wired revision batched all visible callbacks before thinking callbacks, ordered differently from the original immediate interleaving, and carried an arbitrary iteration guard plus an inaccurate held-console comment. A mixed-order regression reproduced the deviation in job `20260916T180645-05a6588a814b` (`status=failed`, exit 101); the fix emits callbacks in wire order, removes the guard, and corrects the comment. The earlier wired green job `20260916T180042-78771ee26d7f` is superseded because its assertions only checked joined text, not callback order.

Verification used the full supported command, `testctl --project chatbot-rust --suite test --repo /workspace/chatbot-rust`: the new decoder plus characterization (original chat wiring untouched) passed in job `20260916T175420-4b7dbb22aa88`; the corrected wired implementation passed in job `20260916T181236-a3251f9db599` (`status=passed`, exit 0). Logs are `temp/test-logs/modularity-batch2-baseline.log`, `temp/test-logs/modularity-batch2-order-red.log` (expected regression failure), and `temp/test-logs/modularity-batch2-final.log`. No application source changed after the final passing run. No GPU, APK, device or live-deployment validation is claimed.

Implementation and this verification record belong to the pending local commit for this batch, based on `87f962b`. Rebuild/restart the webserver on the host to deploy it.

**Next entry point:** finishing the TTS backend-result/HTTP boundary (MOD-011) is the next independent slice; larger session/service/voice ownership changes remain open. SEC-002/003 and COR-001/002 retain their separately recorded investigation requirements. The six later whole-codebase passes remain unstarted.

## Session 005 — TTS backend-result boundary, 2026-09-17

The user authorized the MOD-011 backend slice as a primary implementation worker with no redelegation or commit. The worker personally read the synthesis/HTTP flow, route callers, error mappings, codec ownership and existing TTS tests before extracting the seam.

**MOD-011 backend extraction verified:** private `chatbot-server/src/tts/backend.rs` owns provider synthesis and returns owned PCM plus sample rate (`synthesize_pcm` → `SynthesizedPcm`), never an Axum response. It holds the provider request shapes, the shared provider HTTP client, WAV parsing, per-provider fade, the silence fallback and backend error mapping with the existing `HttpError` adapter. `tts.rs` keeps token admission/cache/replay/cancel, access policy, codec conversion, HTTP rendering, and the encoded-size cache cap as an explicit post-encode check: oversize encoded clips are rejected with the same 400 `Invalid request body` status/message and `tts::stream::cache` context with the generating flag reset, so the token stays retryable. Provider requests, default rates, fade differences, error statuses/messages and log contexts are preserved verbatim; only the tracing target of moved log calls follows the module path (`chatbot_server::tts::backend`). No existing tests were modified. Codec, text-normalization, browser sentence policy, route and token ownership are unchanged; a longer-lived token-session owner remains open.

Verification used the full supported command, `testctl --project chatbot-rust --suite test --repo /workspace/chatbot-rust`: the four new `tts_backend_boundary` HTTP characterization tests (fish WAV rate/bytes/replay, kokoro WAV rate/fade/replay, kokoro default-rate fallback, oversize rejection with retry reset) passed against the original implementation in job `20260917T010823-f68f1d440b58`; the refactored implementation passed in job `20260917T011458-bba885ff78f1` (both `status=passed`, exit 0). Logs are `temp/test-logs/modularity-mod011-baseline.log` and `temp/test-logs/modularity-mod011-final.log`. No application source changed after the final passing run. No GPU, APK, device or live-deployment validation is claimed.

Implementation and this verification record belong to the pending local commit for this batch, based on `6ddcc33`. Rebuild/restart the webserver on the host to deploy it.

**Next entry point:** MOD-011 retains only the token-session lifetime question; larger session/service/voice ownership changes remain open. SEC-002/003 and COR-001/002 retain their separately recorded investigation requirements. The six later whole-codebase passes remain unstarted.

## Session 006 — TTS token-store boundary, 2026-09-17

The user authorized the next modularity batch on `modularity-refactor`. The primary reviewed the token lifecycle before delegating the store extraction and reviewed the resulting implementation. Characterization tests (prune/expiry/eviction/collision) plus the existing inline capacity test moved verbatim into the new module.

**MOD-011 store extraction verified:** private `chatbot-server/src/tts/store.rs` owns the token-session lifecycle (`PendingTtsStore` over an `RwLock` map): admission with prune/evict-or-reject, `begin` arbitration into cached audio, first generation with a lease, busy, missing or exhausted, `cancel`, and a `GenerationLease` (`complete`/`fail`/drop) that releases the generating flag. `tts.rs` keeps one global `Lazy` store plus token minting, access policy, codec conversion, HTTP rendering, and the encoded-size cache cap with retry reset; handlers hold no map accesses and no lock crosses synthesis. TTL (10m), cap (128), oldest-cached-then->=60s-ungenerated-nongenerating eviction, three cached replays, statuses/messages/headers, the 8 MiB cap, missing-cancel 204, the invalid-token debug log, and token-collision overwrite are preserved verbatim; no silent fixes. Poison behavior is unchanged: store operations expect with `tts lock` exactly where the parent did, while lease drop stays best-effort. Six new store tests (busy, drop reset, success caching, three-replays-then-exhaustion, cancel-while-generating without reinsertion, independent stores) pass with the moved suite and the full HTTP coverage. No existing tests were modified. MOD-011 scoped store ownership is complete; the single process-global store remains a MOD-003 composition lead and browser sentence policy stays a separate earlier stage.

Verification used the full supported command, `testctl --project chatbot-rust --suite test --repo /workspace/chatbot-rust`: the original implementation plus characterization passed in job `20260917T203605-4e0a8690a406`; the refactored implementation passed in job `20260917T204638-899441c20432` (both `status=passed`, exit 0). Logs are `temp/test-logs/modularity-mod011-store-baseline.log` and `temp/test-logs/modularity-mod011-store-final.log`. An intermediate final attempt failed only on a borrowck error in two new tests (`status=failed`, exit 101); production code was unchanged by that fix. No application source changed after the final passing run. No GPU, APK, device or live-deployment validation is claimed.

Implementation and this verification record belong to the pending local commit for this batch, based on `36752c8`. Rebuild/restart the webserver on the host to deploy it.

**Next entry point:** MOD-011 is complete for its scoped store ownership; larger session/service/voice ownership changes remain open. SEC-002/003 and COR-001/002 retain their separately recorded investigation requirements. The six later whole-codebase passes remain unstarted.

## Session 007 — shared generation dispatch, 2026-09-17

The user authorized the next modularity batch on `modularity-refactor`. Review of both generation handlers, provider/search modules and existing tests identified a shared dispatch boundary that keeps the existing OpenAI-owned message DTO. The primary reviewed the dispatch implementation before delegation and compared both handler diffs with the extracted module afterward.

**MOD-007 scoped dispatch verified:** `chatbot-server/src/providers/generation.rs` owns the closed `GenerationProvider` enum, core-to-DTO mapping and the search-gated stream entry point (`build_provider` / `map_core_messages` / `dispatch_stream`); `providers/mod.rs` declares the module. `chat.rs` and `regenerate.rs` keep request validation with the unsupported-provider guard earlier, construction timing, saved-turn rendering with append-versus-replace (`None` vs `insertion_index`), capture-derived versus payload user text, stream guards/finalizers and response building. Construction timing, provider-specific construction error strings, the exact search gating (OpenAI `web_search`+Brave; XAI Brave only when `web_search && !xai_search`, OpenAI-compatible search then native fallback on setup errors only), the three fallback warnings, truncation metrics, and all error/stream rendering strings are preserved verbatim; only the tracing target of the moved construction/fallback logs follows the new module path. No traits, global DI, or lease rewrite; provider-neutral DTOs remain later scope. No existing tests were modified and no provider/search/brave/tool production code changed.

Verification used the full supported command, `testctl --project chatbot-rust --suite test --repo /workspace/chatbot-rust`: the original implementation plus 15 new `generation_dispatch` characterization tests passed in job `20260917T212346-860fab0c728a`; the refactored implementation passed in job `20260917T213003-175cbdaa3629` (both `status=passed`, exit 0). The new suite exercises actual `/chat` and `/regenerate` handlers across search tool/direct/disabled/no-Brave paths, stream error rendering with no-persist/preserved-original history, and XAI native/Brave/multimodal dispatch through a local mock Responses API with no new production stub. Logs are `temp/test-logs/modularity-mod007-baseline.log` and `temp/test-logs/modularity-mod007-final.log`. Only comments and documentation changed after the final passing run. No GPU, APK, device or live-deployment validation is claimed.

Implementation and this verification record belong to the pending local commit for this batch, based on `4bf36a0`. Rebuild/restart the webserver on the host to deploy it.

**Next entry point:** MOD-007 scoped dispatch is complete with the shared DTO still open; larger session/service/voice ownership changes remain open. SEC-002/003 and COR-001/002 retain their separately recorded investigation requirements. The six later whole-codebase passes remain unstarted.

## Session 008 — shared message ownership, 2026-09-17

The next authorized modularity batch addresses MOD-007 message ownership. Consumer inventory covered generation, message utilities, XAI, search, the OpenAI internals and `payload::ChatCompletionRequest`; no test-tree or core consumers used the old path. Primary review compared the moved types and constructors with the original definitions and checked every production import change.

**MOD-007 message ownership verified:** `chatbot-server/src/providers/messages.rs` owns `ContentPart`/`ImageUrlPart`/`ChatMessageContent`/`ChatMessagePayload` and the `system`/`user`/`user_with_content`/`assistant` constructors verbatim; all production imports resolve through the neutral module. `providers::openai::messages` remains as a re-export so existing paths keep compiling. Serialization, constructors, images/tool-call/`None` omission, the XAI `input_text`/`input_image` mapping and all behavior are preserved; no existing tests were modified and no traits or schema redesign were introduced. Ownership is decoupled but the representation retains OpenAI-compatible serialization; no comprehensive provider-neutral domain redesign is claimed. `docs/design.md` no longer claims a trait-based provider abstraction: dispatch is recorded as the concrete `GenerationProvider` enum.

Verification used the full supported command, `testctl --project chatbot-rust --suite test --repo /workspace/chatbot-rust`: the original implementation plus 4 new `provider_messages` upstream-capture characterization tests (user text shape with envelope and null omission, image text-plus-`image_url` parts, system plain string, second-turn assistant plain string; XAI mapping already pinned by `generation_dispatch.rs`) passed in job `20260917T215233-52d0e6ae1e67`; the refactored implementation passed in job `20260917T215738-03aef1cabdc2` (both `status=passed`, exit 0). Logs are `temp/test-logs/modularity-mod007-messages-baseline.log` and `temp/test-logs/modularity-mod007-messages-final.log`. No GPU, APK, device or live-deployment validation is claimed.

Implementation and this verification record belong to the local commit titled `Move shared provider messages out of OpenAI adapter`, based on `6768d68`. Only comments, whitespace and documentation changed after the final passing run. Rebuild/restart the webserver on the host to deploy it.

**Next entry point:** MOD-007 ownership is complete for the shared DTO with OpenAI-compatible serialization retained; larger session/service/voice ownership changes remain open. SEC-002/003 and COR-001/002 retain their separately recorded investigation requirements. The six later whole-codebase passes remain unstarted.

## Session 009 — encryption-key cookie boundary, 2026-09-17

`chatbot-server/src/enc_key_cookies.rs` now owns encryption-key header/cookie extraction, account-cookie naming, cookie construction and verified promotion. The implementation moved verbatim from `chat_utils.rs`; explicit re-exports preserve existing public paths and callers. Request authorization, proxy identity, streaming guards and core storage are unchanged. MOD-008 is partially remediated; broader request-context and session/remember-cookie ownership remain open.

Seventeen new characterization tests in `chatbot-server/tests/enc_key_cookies_boundary.rs` cover header/account/generic precedence, empty and URL-encoded values, exact cookie flags and lifetimes, and verified promotion/fallback behavior. Existing tests were unchanged. The full supported executor suite passed before extraction (`20260917T221152-08c77a3e4e64`) and after extraction (`20260917T221739-1de89cde591d`), both exit 0. Logs: `temp/test-logs/modularity-mod008-cookies-baseline.log` and `temp/test-logs/modularity-mod008-cookies-final.log`. Primary review checked the moved implementation, compatibility exports, new tests and both logs, including provider-configuration validation. Only documentation changed after the final run.

This batch is recorded in the local commit titled `Extract encryption-key cookie transport helpers`, based on `1dcdca2`. Rebuild/restart the webserver on the host to deploy. Next selection: narrow typed-error or history-facade visibility boundaries, preserving existing HTTP contracts. Phase 1 continues; the main-model read-only completion review has not begun.
