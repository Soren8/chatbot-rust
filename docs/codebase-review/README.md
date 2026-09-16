# Codebase review program

## Purpose and authority

Review the entire repository across seven separate passes: modularity; simplicity; abstractions, reuse, and duplication; security and privacy; performance and resource use; test coverage and quality; documentation accuracy. The goal is evidence-backed improvements that preserve intended behavior, not a rewrite or a target number of findings.

The primary reviewer personally reads the implementation and relevant callers before defining remediation. Implementation workers may receive bounded fixes afterward; they do not perform the initial review, redelegate, or commit. Each worker has exclusive file ownership. The primary reviewer examines the resulting diff and integration behavior before accepting it.

Complete a pass, consolidate related findings, and agree on a bounded remediation batch before proceeding to the next pass. A confirmed serious security or data-loss issue may interrupt this sequence. Incidental observations from later passes are recorded without claiming those passes are complete.

## Records

- [Coverage](coverage.md) assigns tracked paths to review units and records independent progress for every pass.
- [Findings](findings.md) records evidence, uncertainty, disposition, correction proposals, and verification requirements.
- [Boundary map](boundaries.md) records observed dependencies and flow-tracing progress. It describes implementation evidence separately from intended architecture.

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

## Current checkpoint — session 001, 2026-09-16

Established the seven-pass inventory and reviewed the Rust workspace dependency direction, server startup/router composition, middleware definitions, and HTTP error adapter. Supporting reads followed the home handler, test-workspace construction, and selected core session/config/history boundaries. No full application flow has yet been traced end to end.

The composition unit's modularity review is complete within its stated scope. Core sessions and shared test support remain partial. Two structural findings are confirmed; three cross-pass leads need investigation. No finding has been approved for implementation. No workers were used, and no application code, tests, or operational configuration changed.

Verification: checked inventory assignment against tracked paths, document references, baseline evidence, and `git diff --check`. The application suite was not run for this documentation-only checkpoint. No current application-test result is claimed.

**Next entry point:** continue modularity unit C02 in `chatbot-core/src/session.rs`: read lines 740–759 and 1058–1796, then trace consumers in `chatbot-server/src/chat_utils.rs`, `chat.rs` (remaining lines 231–452), `regenerate.rs`, and relevant state-mutating routes. Consult `docs/design-history-store.md` and `docs/design-history-chunks.md` before evaluating durable-state ownership. Review the existing behavioral tests before proposing any split. Resolve the scope of MOD-001/MOD-002 without broadening into a blanket dependency-injection rewrite.
