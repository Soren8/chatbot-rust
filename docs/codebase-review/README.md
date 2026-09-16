# Codebase review program

Latest resume point: [session 004 — shared stream decoder](#session-004--shared-stream-decoder-2026-09-16). Earlier checkpoints record their original scope and status.

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
