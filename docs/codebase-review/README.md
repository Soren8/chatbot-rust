# Codebase review program

Latest resume point: [session 023 — router resource ownership](#session-023--router-resource-ownership-2026-09-18). Earlier checkpoints record their original scope and status.

## Overall phase status and review gate

Current remediation count: twenty-one committed batches through session 023. Phase 1 remains in progress; the completion-review gate below still applies.

## Session 023 — router resource ownership, 2026-09-18

MOD-003 partial remediation: production composes owned identity, TTS tokens and rate counters in `AppServices`. Compatibility constructors preserve global state and lazy initialization; live limits remain configured globally. Four new HTTP tests prove cross-router token/replay/cancel isolation, independent per-client/global rate budgets and compatibility counter sharing. Primary reviewed the implementation, wiring and tests. Existing tests remain intact. Final full suite `20260918T064027-ec6ef22c6217` passed; log `temp/test-logs/modularity-mod003-resources-final.log`. Later account-input reviewed suite `20260918T071408-72c5505f8b38` also passed these changes and provider-config validation. Commit title: `Compose owned TTS tokens and rate counters`, based on `545c27f`. Full application isolation and phase-1 completion review remain open.

Phase 1 of seven is modularity: the initial whole-codebase assessment is complete, and bounded remediation remains in progress. Phases 2–7 (simplicity, abstractions/reuse, security/privacy, performance, test quality, documentation) have not started. The user authorized continued phase-1 work and requested a main-model read-only review after phase-1 remediation, before phase 2. That review is still pending; individual passing batches do not mark phase 1 complete.

Verified boundaries include live naming/Fernet helpers, browser stream decoding, TTS text/backend/token-store ownership, shared generation dispatch/message ownership, encryption-key cookie transport, narrowed history APIs and typed key/prepare validation. Remaining structural work includes broader typed core outcomes, session/chat separation, generation lease ownership, application-service composition, history representations, broader request context, browser/native voice coordination, credential-cache interfaces, voice-service lifetimes and distribution settings. Auto support requires a contract decision. Partial findings and compatibility decisions must receive explicit dispositions before the phase-completion review; cross-pass security/correctness leads remain separately tracked.

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

## Session 010 — history facade tightening, 2026-09-17

The eighth remediation batch narrows MOD-005's public history boundary. Removed the unused service-level `HistoryService::commit_snapshot` bypass; named service mutations retain the private store's CAS writer. Removed the unused `SetCache` facade export, its two unused helpers (`with_limits`, `invalidate_user`), and seven storage-format exports (`BlobFormat`, `HeaderV1`, `ManifestPair`, `ManifestV1`, `PairPayloadV1`, `ImagePayloadV1`, `ThumbPayloadV1`). Domain types and `SetPayloadV1` remain available for current callers and migration compatibility tests. This is a Rust public-API reduction for hypothetical out-of-tree consumers; repository callers and HTTP behavior are preserved.

Caller inventory found no consumers of the removed APIs. Existing history service, CAS/conflict, migration, image and cache tests provided behavioral coverage; no tests were modified or deleted. Full executor baseline `20260917T223122-938b876265b4` and final `20260917T223601-ac2cfb4c7d05` passed with exit 0 using `testctl --project chatbot-rust --suite test --repo /workspace/chatbot-rust`. Logs are `temp/test-logs/modularity-mod005-baseline.log` and `temp/test-logs/modularity-mod005-final.log`. Primary review checked every deletion/export change, retained internal writer call sites, passing provider-config validation and matching warning sets. Only documentation changed after the final run.

This batch belongs to the local commit titled `Narrow history facade to used service APIs`, based on `a54c02e`. MOD-005 remains partial: logical versus materialized snapshot representations and cache normalization still need a focused design. Next entry point is a bounded typed-core-error or generation-lifecycle slice. Phase 1 remediation continues; phases 2–7 and the requested main-model read-only completion review remain pending. Host webserver rebuild/restart is required to deploy.

## Session 011 — typed encryption-key validation, 2026-09-17

MOD-001 now has a narrow typed boundary: `session::validate_encryption_key_for_user` returns `EncryptionKeyValidationError::{Missing,Invalid,StoreUnavailable}`. Direct server callers in sets, memory, reset and preferences use one HTTP adapter. `require_encryption_key` retains its public `ServiceResponse` compatibility contract for core orchestration; two mirror helpers use that adapter. Exact 401/500 messages, verifier non-enrollment, cause logs and error counting are preserved. Chat/regenerate handlers, history status mappings, locks and cryptography are unchanged. Broader removal of HTTP-shaped core outcomes remains open.

Five new HTTP characterization tests passed before extraction; two additional mapper regressions cover server-error counting. Primary review caught a lost counter increment and extra 5xx log in the first adapter. The counter regression failed before correction and the complete suite passed after correction. Existing tests were unchanged. Verification command: `testctl --project chatbot-rust --suite test --repo /workspace/chatbot-rust`.

Evidence: clean baseline `20260917T224924-a885dc4da3c6`; pre-extraction characterization `20260917T225347-9b10d5a32e5f`; initial extraction `20260917T230028-fe028c782ca5` (all passed); instrumentation regression `20260917T230706-ee47aad2389d` (expected failure, counter 0 instead of 1); corrected final `20260917T230940-a5d05ec05060` (passed, exit 0, all seven new tests and provider-config validation green). Logs are `temp/test-logs/modularity-mod001-keys-{baseline,char,final,instrumentation-red,instrumentation-final}.log`. The final run supersedes the initial extraction result. Store-failure response/count mapping is tested directly; an actual failing filesystem-backed store was not injected. Primary reviewed all production adapters and the regression evidence. Only comments and documentation changed after the final run.

Local commit title: `Return typed encryption-key validation errors`, based on `9b3e02a`. Next entry point: continue bounded core-outcome or generation-lease ownership work. Phase 1 and the requested main-model read-only completion review remain pending; phases 2–7 are unstarted. Rebuild/restart the webserver on the host to deploy.

## Session 012 — typed prepare validation, 2026-09-17

MOD-001 partial remediation: chat/regenerate preparation returns `PrepareError::Validation(PrepareValidationError)` for empty messages, invalid set names/IDs and invalid/missing regeneration pair indices. Other failures retain a transitional `Service(ServiceResponse)` carrier. HTTP consumers choose the existing saved error-turn path for nonempty messages, or a typed raw-400 mapper otherwise. Lookup failures retain their separate service-response path. Locks, finalizers, authentication and history error policies are unchanged. This changes the Rust prepare-result error type; no other in-repository consumers needed migration.

Ten new router tests in `prepare_validation_boundary.rs` characterize status/content/body behavior and successful same-session regeneration after an out-of-range failure. They passed before extraction and after. Existing tests were unchanged. Primary reviewed all production diffs and tests, and requested preserving the structured raw-400 `body` log field via `api_error_json`; the log target now follows the HTTP error module. Saved-turn branches do not invoke that mapper. The tests do not assert tracing metadata or cover expiry/recreation during generation.

Full-suite command: `testctl --project chatbot-rust --suite test --repo /workspace/chatbot-rust`. Characterization baseline `20260917T233812-71888f6e8ee4` passed; extraction final `20260917T234712-dfb4f1a9f34f` passed after two corrected compilation failures; reviewed final `20260917T235325-bd666bc570e5` passed after the log-field adjustment. All ten new tests and provider-config validation are green. Logs: `temp/test-logs/modularity-mod001-prepare-{baseline,final,reviewed-final}.log`. Only documentation changed after the reviewed final.

Local commit title: `Return typed chat preparation validation errors`, based on `8eacc78`. MOD-001 remains open for remaining service outcomes. Generation-lease work requires a dedicated disposition of ID-based release versus acquired-entry lifetime; do not silently change expiry semantics in an extraction. Phase 1 remediation and its main-model read-only completion review remain pending, with phases 2–7 unstarted. Host webserver rebuild/restart is required to deploy.

## Session 013 — prompt-input boundary, 2026-09-18

MOD-002 partial remediation: pure prompt packing now accepts borrowed `PromptInput` through `prepare_prompt_messages`. Its inputs are system prompt, memory, history, resolved context size and the thoughts flag. The existing public `prepare_chat_messages(&ChatContext, ...)` delegates without additional input cloning and retains provider-default resolution. Production callers and existing tests remain unchanged; the compatibility wrapper still imports session types, while the packing algorithm no longer consumes them. Broader session/identity/orchestration separation remains open.

Existing chat tests provided the pre-extraction baseline, including memory, thoughts, truncation and image handling. Seven new post-extraction boundary tests exercise the smaller API plus explicit/default wrapper compatibility. Primary reviewed the mechanical packing changes and strengthened the new image assertion so loss of the history image cannot pass silently. A malformed image fixture in a new test was corrected during development; existing tests were not modified. The initial failed-run log was overwritten by the worker, so only its report remains for that intermediate failure.

Verification: full `testctl --project chatbot-rust --suite test --repo /workspace/chatbot-rust` baseline `20260918T004934-679d3f8ceba2`, extraction final `20260918T005646-e26a1428fa71`, and reviewed final `20260918T010245-e2177aad8c3b` all passed. The reviewed final includes all seven new tests and provider-config validation. Logs: `temp/test-logs/modularity-mod002-prompt-{baseline,final,reviewed-final}.log`. The baseline did not contain the new boundary tests. Only documentation changed after the reviewed final.

Local commit title: `Decouple prompt packing from session context`, based on `edfa3e3`. Eleven remediation batches are complete; phase 1 remains in progress and phases 2–7 are unstarted. Next work should address another remaining ownership boundary or explicitly disposition a larger finding; the requested main-model read-only phase-completion review remains pending. Rebuild/restart the host webserver to deploy.

## Session 014 — request-transport ownership, 2026-09-18

MOD-008 partial remediation: `chatbot-server/src/request_context.rs` owns raw Cookie/CSRF header extraction and client-IP selection. Duplicate helpers in sets/memory and equivalent inline parsing in chat, regenerate, TTS/STT, reset, preferences, home, login/logout/signup, client logs and rate limiting delegate to it. The rate limiter retains borrowed cookie extraction; other consumers retain owned values. `chat_utils::get_ip` remains a compatibility re-export. IP forwarding precedence, malformed/empty/duplicate header handling, identity creation versus lookup, CSRF messages and per-route authorization decisions are unchanged. This does not resolve broader authenticated request-context ownership or SEC-002.

Existing IP/CSRF/authentication tests passed before extraction. Eighteen new post-extraction tests cover transport edge cases and the chat/client-logs CSRF distinction. Primary reviewed every production diff and both new files, then required serialization of the two route tests because their fixtures mutate global cwd/environment/config. Existing tests were unchanged. Pure header tests do not use workspace fixtures.

Full command: `testctl --project chatbot-rust --suite test --repo /workspace/chatbot-rust`. Baseline `20260918T012122-4fd4dcdfb195`, extraction final `20260918T012843-718960cb230a`, and reviewed final `20260918T013542-d4bd42b45480` all passed, including provider-config validation. Logs: `temp/test-logs/modularity-mod008-request-{baseline,final,reviewed-final}.log`. The new tests were added after the baseline. Only documentation changed after reviewed final.

Local commit title: `Consolidate request transport extraction`, based on `e677bc8`. Twelve batches are complete; phase 1 remains in progress. Remaining work includes broader session/service composition, generation lifetime, history representation and browser/native voice ownership. Resolve or explicitly disposition remaining structural findings before the main-model read-only completion review; phases 2–7 remain unstarted. Host webserver rebuild/restart is required to deploy.

## Session 015 — HTTP identity ownership, 2026-09-18

MOD-002 partial remediation: `chatbot-core/src/session_identity.rs` owns the HTTP identity store, DTOs, cookie/token helpers, CSRF validation, bootstrap/context lookup, rate-limit identity and login/logout rotation. `session.rs` re-exports the public API; it retains chat state, generation locks, prepare/finalize/persistence and the combined purge entry point. A crate-visible HTTP purge hook composes the two stores, and the guest-prefix constant is crate-visible for the existing chat cipher gate. Public callers and existing tests require no migration.

Primary reviewed the full removed/moved blocks and purge composition: HTTP minimum-60-second timeout, raw chat timeout, singleton initialization, lock order, cookie flags and identity creation/lookup semantics are preserved. The unknown-cookie rate-limit identity fallback is unchanged; SEC-002 remains separately tracked. Expiry itself has no new clock-controlled test; preservation is supported by source review and existing integration coverage.

Six new lifecycle characterization tests passed before and after extraction through the existing `session::` API: guest bootstrap/cookie shape, stable reuse, CSRF rejection/match, login rotation, logout rotation and noncreating rate-limit identity. They serialize their shared workspace state. A new-test compile error using equality on `SessionError` was fixed before the green baseline; existing tests were unchanged. Provider-config validation and the full suite pass.

Command: `testctl --project chatbot-rust --suite test --repo /workspace/chatbot-rust`. Baseline `20260918T014810-c8c009c7bdbc`; final `20260918T015409-61aad3c42477`, both passed. Logs: `temp/test-logs/modularity-mod002-identity-{baseline,final}.log`; initial compile failure `20260918T014643-497ad3303a55` is preserved in `modularity-mod002-identity-baseline-compilefail.log`. Only comments/documentation changed after final.

Local commit title: `Separate HTTP session identity from chat orchestration`, based on `f664908`. Thirteen batches are complete; MOD-002 remains open for broader orchestration boundaries, and MOD-003 still covers global service composition. Phase 1 and its main-model read-only completion review remain pending; phases 2–7 are unstarted. Host webserver rebuild/restart is required to deploy.

## Session 016 — prepare policy errors, 2026-09-18

MOD-001 partial remediation: core prepare emits typed `PreparePolicyError::{Busy, PremiumRequired}`; the server renders the exact 429/403 JSON bodies. User-store failures retain the service carrier. Primary reviewed all production changes and new tests: lock acquisition/release, saved-400 handling and logging/counter behavior are unchanged.

Nine new serialized route characterization tests cover both busy routes, guest rejection, authenticated free-user rejection, premium success and lock reuse following rejection. They passed against the original implementation before extraction and unchanged afterward. Existing tests were untouched; provider-config validation passed. Full command: `testctl --project chatbot-rust --suite test --repo /workspace/chatbot-rust`. Baseline job `20260918T021259-87f815022547`; final `20260918T021924-d37e30d3b1fb`, both passed. Logs: `temp/test-logs/modularity-mod001-policy-{baseline,final}.log`. Only documentation/comments changed after final.

Local commit title: `Return typed prepare policy errors`, based on `711c9ed`. Fourteen batches complete; broader core response removal and lifecycle ownership remain open. Phase 1 completion review is pending; phases 2–7 remain unstarted.

## Session 017 — prepare history errors, 2026-09-18

MOD-001 partial remediation: typed `PrepareHistoryError` replaces history response construction during prepare. The cloneable projection retains unauthorized, missing, conflict/version, invalid-input, forbidden and internal outcomes. Both generation routes preserve saved error turns for nonempty-message 400s. Prepare missing-set remains 400 rather than the general mapper's 404; conflict retains only `error` and `current_version`. Core cause logs, server 500 instrumentation and raw-400 structured `body` logging are preserved. Key/user-store/session-init carriers and finalizer rendering remain open.

Four new route characterizations passed before/after extraction: chat/regenerate missing-set saved turns, lock recovery, wrong-key raw 401 and oversized-prompt saved error. Wrong-key exercises the retained encryption gate, not history decryption. Primary added review requirements for raw-400 log-field parity and four direct mapper tests, including otherwise race-dependent conflict and internal-error counter. Existing tests were unchanged.

Full command: `testctl --project chatbot-rust --suite test --repo /workspace/chatbot-rust`. Baseline `20260918T022951-0bd17403a87f`, final `20260918T023620-e12d60e16461`, reviewed final `20260918T034644-c8beb77a06fa`: all passed, including provider-config validation. Logs: `temp/test-logs/modularity-mod001-history-{baseline,final,reviewed-final}.log`. Reviewed final includes the parallel voice-text batch; primary reviewed the Rust diff, handler branching and all eight new tests. No claim of a deterministic route-level conflict/store-failure reproduction.

Local commit title: `Return typed prepare history errors`, based on `bc140fd`. Fifteen remediation batches complete; phase 1 and its completion-review gate remain open.

## Session 018 — shared voice text, 2026-09-18

MOD-009/016 partial remediation: `static/voice-text.js` owns sentence splitting/completion, TTS normalization, joining, amend eligibility and sentence-offset lookup. `chat.js` keeps adapters, its 2000ms amend-window policy and all queue/voice coordination. No barge-in thresholds changed. Primary reviewed the extracted algorithms, template load order and fixture migrations.

The user explicitly approved migrating source-bound voice tests. Existing desktop/native sentence and exhaustion fixtures now import the actual shared text unit; their queue scenarios/assertions remain intact. Structural checks refer to the new owner; queue checks stay on `chat.js`. Four new Rust tests cover stable-import behavior, parsing, packaging/delegation and explicit window wiring. Source-bound queue tests remain a MOD-016 limitation.

Full command: `testctl --project chatbot-rust --suite test --repo /workspace/chatbot-rust`. Initial three-helper checkpoint: final `20260918T030051-5a4c88dc44a5` passed, but its baseline had two expected wiring failures and an intermediate new-test failure log was overwritten. Expanded characterization baseline `20260918T032717-84ec40f7fe3c` and expanded final `20260918T033914-d74887b0a0b3` passed. Expanded failed attempts are preserved: baseline test expectations `20260918T032011-d92e70621661`, syntax error during extraction `20260918T033446-6992cbe5f3ee`. Logs use `temp/test-logs/modularity-mod009-voice-text-expanded-{baseline,baseline-red,final,final-red}.log`. Later history reviewed-final also passed with these changes. Provider configuration validation passed.

Local commit title: `Extract shared browser and native voice text utilities`, based on `8a200d7`. Sixteen remediation batches complete; browser state/voice coordination and phase-1 completion review remain open. Host webserver rebuild/restart is required for the new image-baked asset and template wiring.

## Session 019 — normalized history cache, 2026-09-18

MOD-005 representation remediation: the user explicitly approved correcting warm `load_logical` output after characterization showed inline image data where cold reads returned references. Private `LogicalSnapshot` now marks store-produced snapshots; the cache accepts this type only. Existing commit normalization returns its sealed text for cache insertion, avoiding a second normalization pass or post-commit reload. Public materialized reads retain a separate owned copy; versions, IDs and CAS remain intact. Whole-blob migration returns its durable representation with no fabricated pair IDs. Primary rejected a substring-based invariant that would panic on accepted malformed image tags; store provenance establishes the boundary instead.

Seven new tests cover direct/captured append, regenerate, fork, warm/cold equivalence and literal malformed-marker preservation. Materialized reads compare decoded image bytes and verify 32×32 dimensions; these are fixture-scale checks, not a large-photo benchmark. Mechanical cache/store unit-test signature changes retain every pre-task assertion. No handler/API migration was bundled.

Full command: `testctl --project chatbot-rust --suite test --repo /workspace/chatbot-rust`. Characterization baseline `20260918T035726-867d7f6352d5` passed after a preserved fixture-only failure (`20260918T035530-90f3ad4ec14a`, two handles to one redb file). Two new equivalence regressions failed as intended in `20260918T041821-110ced3c467c` and passed unchanged after correction. Final `20260918T042655-c48a4a364800`; reviewed final `20260918T043444-6c6e4d1e6375`, both passed including provider-config validation. Intermediate compile and V1-fork failures were preserved (`20260918T042401-f3e096e471dc`, `20260918T042454-005615f87381`). Logs: `temp/test-logs/modularity-mod005-snapshots-{baseline,normalize-red,normalize-final,reviewed-final}.log` and uniquely named failed-attempt logs.

Local commit title: `Cache normalized logical history snapshots`, based on `4085b3b`. Seventeen remediation batches complete. MOD-005's cache-shape invariant and unused-facade bypasses are addressed; public compatibility DTOs and materialized prepare captures remain explicit boundaries, with slim captures/layered caching left for focused follow-up rather than claimed here. Phase 1 remains open.

## Session 020 — owned HTTP identity, 2026-09-18

MOD-003 partial remediation: `HttpSessionStore` owns identity state and accepts timeout at construction plus CSRF policy per operation. Six lifecycle operations have one implementation; existing free APIs delegate to the same single production global. HTTP minimum-60-second timeout, cookie flags, lookup creation rules and unknown-cookie rate identity are preserved. Four independent-store tests cover bootstrap/login/logout/CSRF isolation, noncreating lookup and timeout policy without ambient config.

Primary found early-return delegates initially initialized the global too soon; the corrected CSRF-disabled/missing/empty and missing-cookie paths retain lazy initialization. A dedicated fifth test changes temporary config before first real bootstrap and verifies the later timeout wins. Primary reviewed the complete move, all five tests and final evidence. No clock-controlled expiry claim is made.

Baseline is the preceding unchanged green suite `20260918T043444-6c6e4d1e6375`, reused without rerunning. Full command: `testctl --project chatbot-rust --suite test --repo /workspace/chatbot-rust`. Final `20260918T044642-d78a66509158`; reviewed final `20260918T045405-b76137ee7465`, both passed including provider-config validation and existing six identity boundary tests. Logs: `temp/test-logs/modularity-mod003-identity-owned-{final,reviewed-final}.log`.

Local commit title: `Make HTTP identity state explicitly owned`, based on `c63c994`. Eighteen remediation batches complete. Production router composition still uses global APIs; MOD-003 and phase-1 completion review remain open.

## Session 021 — router identity composition, 2026-09-18

MOD-003/008 partial remediation: production startup constructs one HTTP identity store for both router and purge. All identity-dependent handlers and middleware use request-injected `RequestIdentity`, including remember restoration and account-key-cookie precedence. Missing injection is a construction error rather than a silent global fallback. `build_router` keeps the existing lazy-global path for direct compatibility consumers. Owned purge calls only its own HTTP store plus the shared chat-only purge helper; primary corrected an initial accidental purge of the unrelated global HTTP store.

Six route tests prove cross-router cookie/CSRF/login isolation, default-global compatibility, preserved unknown-cookie log/rate behavior and owned-account-key selection. One separate-process test proves owned purge does not initialize global HTTP identity. Existing tests were untouched. History/chat, rate counters, remember/user stores and config remain shared; no full-application isolation claim is made. SEC-002 policy remains unchanged.

Baseline reused preceding green `20260918T045405-b76137ee7465`. Full command: `testctl --project chatbot-rust --suite test --repo /workspace/chatbot-rust`. Final `20260918T052122-07de4775eb68`, reviewed final `20260918T053800-0895f05d4d11`: passed, including provider-config validation. Logs: `temp/test-logs/modularity-mod003-router-identity-{final,reviewed-final}.log`; failed new-fixture attempts are preserved under `*-final-attempt1-red.log` (rate-limit environment precedence) and `*-reviewed-final-attempt1-red.log` (global initialization shared between tests, corrected by dedicated binary). Primary reviewed every migrated call site, startup/layer wiring, purge and seven tests.

Local commit title: `Compose HTTP identity through router and background tasks`, based on `c678656`. Nineteen remediation batches complete; broader application composition and phase-1 completion review remain open.

## Session 022 — generation settlement ownership, 2026-09-18

MOD-006 partial remediation: production routes use leased prepare APIs. Non-cloneable `GenerationLease` binds the prepare-time session, delegates persistence/unlock to the existing core finalizers and suppresses its fallback drop release after completion. The stream guard owns the lease-capturing closure and no longer shares a second lock/released flag with handlers. Primary required identity binding inside the lease so completion cannot select another session. Existing prepare/finalize APIs and public `ChatLockGuard` remain compatibility surfaces.

Eight route characterizations passed unchanged before/after extraction: chat/regenerate success, provider error, pre-poll cancel, partial cancel, polled-but-empty cancel, unknown-model saved error and regeneration partial replacement. Six new core tests verify owned release/completion/error/drop and that completing A leaves B busy. Primary reviewed all production edits and tests. Setup failures retain release-before-saved-turn order; response-build failure releases on body drop before returning. Neither branch is forced through fault injection. ID-based expiry/recreation, pre-prepare error-turn unlock behavior and post-commit mirror policy are preserved, not fixed. Typed finalizer outcomes remain open.

Full command: `testctl --project chatbot-rust --suite test --repo /workspace/chatbot-rust`. Baseline `20260918T060140-c76ad550bbb3`, final `20260918T061029-d46f9161ae3c`, reviewed final `20260918T062005-6eeefbb38a9b`: passed including provider-config validation. Logs: `temp/test-logs/modularity-mod006-lease-{baseline,final,reviewed-final}.log`. A compile-error baseline attempt is preserved (`20260918T055504-e8a65113ff79`); a further new-fixture lifetime failure was corrected before the green baseline, with no separate log available in the named evidence set. Existing tests were unchanged.

Local commit title: `Bind generation settlement to an owned lease`, based on `f09a65d`. Twenty remediation batches complete; phase 1 remains open and its main-model read-only completion review is still pending.
