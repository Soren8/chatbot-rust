# Review coverage

## Per-unit review-scope matrix

The matrix records inventory assignment and pass scope, not a certification that a unit is issue-free. `R` means reviewed for that pass; `P` means partial, with scope in the owning pass file; `S` means stale after relevant changes; `B` means boundary/integration review only; `—` means not reviewed. A `B` or `P` retains the specific limits below and in the owning pass. The seven columns are M modularity, S simplicity, A abstractions/reuse, Sec security/privacy, Perf performance/resources, T tests, D documentation.

| Unit | Owned paths, in matching order | M | S | A | Sec | Perf | T | D |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| V01 Third-party browser dependencies | `static/deps/*` | B | B | — | B | B — no performance finding in dependency boundary review | B | B |
| R01 Rust composition | `Cargo.toml`, `chatbot-core/Cargo.toml`, `chatbot-core/src/lib.rs`, `chatbot-server/Cargo.toml`, `chatbot-server/src/lib.rs`, `chatbot-server/src/main.rs`, `chatbot-server/src/background.rs`, `chatbot-server/src/http_error.rs`, `chatbot-server/src/test_instrumentation.rs`, `chatbot-test-support/Cargo.toml` | S | S | S | S | S-PERF-7 compression open (host proxy unknown); S-PERF-8 COOP/COEP open (likely inert; user decision) | R | R |
| C01 Configuration/logging | `chatbot-core/src/config.rs`, `chatbot-core/src/logging.rs` | R | R | R | R | R — reviewed; no finding | R | R |
| C02 Session state/orchestration | `chatbot-core/src/session.rs` | R | R | R | R | PERF-B, PERF-D | R | R |
| C03 Identity/key stores | `chatbot-core/src/user_store.rs`, `chatbot-core/src/remember_store.rs`, `chatbot-core/src/enc_key.rs` | R | R | R | R | S-PERF-5 retained; ordinary in-process users.json RMW fixed (TQ-004); PR-015 first-open initialization uses non-replacing atomic publication; cross-process RMW is not serialized | R | R |
| C04 Durable history | `chatbot-core/src/history/*` | S | S | S | S | PERF-B, PERF-D, PERF-F, PERF-L | R | R |
| C05 Persistence/legacy migration | `chatbot-core/src/persistence.rs`, `chatbot-core/src/legacy_sets_json/*` | R | R | R | R | R — one-time migration; no performance finding | R | R |
| C06 Chat content/images | `chatbot-core/src/chat.rs`, `chatbot-core/src/chat_images.rs` | R | R | R | R | PERF-B | R | R |
| C07 Core rate limiting | `chatbot-core/src/rate_limit.rs` | R | R | R | R | R — reviewed; no finding | R | R |
| C08 Shared naming/Fernet helpers | `chatbot-core/src/names.rs`, `chatbot-core/src/fernet_crypto.rs` | R | R | R | R | R — reviewed; no finding | R | R |
| C09 Core account/session services (post-baseline) | `chatbot-core/src/account_service.rs`, `chatbot-core/src/config_source.rs`, `chatbot-core/src/session_identity.rs` | — | R | R | R | PERF-K | R | R |
| P01 Core agent connectivity (post-baseline) | `chatbot-core/src/agent_connections.rs`, `chatbot-core/src/agent_egress.rs` | — | S | S | S | R — reviewed; no performance finding | R | R |
| C10 Core operation receipts (post-Phase-4) | `chatbot-core/src/operation_receipt.rs`, `chatbot-core/src/connection_receipts.rs` | — | — | — | — | PERF-J (R-PERF-1); R-PERF-5 rejected (bounded, allowlisted writers) | R | R |
| T01 Core integration tests | `chatbot-core/tests/*` | R | P | — | P | PERF-B, PERF-D, PERF-F, PERF-L (cost-bound regressions) | R | B |
| S01 Chat streaming/orchestration | `chatbot-server/src/chat.rs`, `chatbot-server/src/chat_utils.rs`, `chatbot-server/src/regenerate.rs` | S | S | S | S | PERF-A, PERF-B, PERF-D, PERF-R | R | R |
| S02 Authentication/home | `chatbot-server/src/home.rs`, `chatbot-server/src/login.rs`, `chatbot-server/src/logout.rs`, `chatbot-server/src/signup.rs` | S | S | S | S | PERF-T; ordinary in-process users.json RMW fixed (TQ-004); first-open initialization tracked separately as PR-015 | R | R |
| S03 History/memory/preferences routes | `chatbot-server/src/sets.rs`, `chatbot-server/src/memory.rs`, `chatbot-server/src/preferences.rs`, `chatbot-server/src/reset_chat.rs` | S | S | S | S | PERF-S | R | R |
| S04 Providers/search/tools | `chatbot-server/src/providers/*`, `chatbot-server/src/brave.rs`, `chatbot-server/src/search.rs`, `chatbot-server/src/tools.rs` | R | R | R | R | PERF-R; S-PERF-10 retained; search.rs:220 slicing panic handed to later correctness phase | R | R |
| S05 Voice endpoints/codecs | `chatbot-server/src/stt.rs`, `chatbot-server/src/tts.rs`, `chatbot-server/src/tts_opus.rs` | S | S | S | S | PERF-A, PERF-E, PERF-S, PERF-T | R | R |
| S08 Speech-text normalization | `chatbot-server/src/tts/text.rs` | R | R | R | R | R — reviewed; no performance finding | R | R |
| S09 TTS backend synthesis | `chatbot-server/src/tts/backend.rs` | R | R | R | R | PERF-E, PERF-R | R | R |
| S10 TTS token-session store | `chatbot-server/src/tts/store.rs` | S | S | S | S | PERF-J | R | R |
| S06 Operational endpoints/limits | `chatbot-server/src/health.rs`, `chatbot-server/src/client_logs.rs`, `chatbot-server/src/rate_limit_middleware.rs` | S | S | S | S | PERF-K, PERF-T | R | R |
| S11 Server privacy/agent coordination (post-baseline) | `chatbot-server/src/set_privacy_coordinator.rs`, `chatbot-server/src/agent_connections.rs` | — | S | S | S | R — reviewed; no performance finding | R | R |
| S12 Server composition/policy adapters (post-baseline) | `chatbot-server/src/policy.rs`, `chatbot-server/src/generation_deps.rs`, `chatbot-server/src/services.rs`, `chatbot-server/src/identity.rs`, `chatbot-server/src/enc_key_cookies.rs`, `chatbot-server/src/request_context.rs` | — | S | S | S | PERF-R, PERF-S, PERF-T; S-PERF-10 retained | R | R |
| S13 Durable generations/idempotency (post-Phase-4) | `chatbot-server/src/generations.rs`, `chatbot-server/src/idempotency.rs` | — | — | — | — | PERF-D, PERF-J; R-PERF-4 retained (policy choice) | P | R |
| T02 Server integration tests/fixtures | `chatbot-server/tests/*` | R | P | — | P | PERF-A–T regression coverage (see performance.md batch records) | R | B |
| T03 Shared test support | `chatbot-test-support/src/*` | R | R | R | R | R — reviewed; no performance finding | R | B |
| S07 Server examples/protected configuration | `chatbot-server/examples/*`, `chatbot-server/.config.yml` | B | B | — | B | B — no performance finding in example/protected-config boundary review | B | B |
| W01 Browser chat UI | `static/chat.js` | S | S | S | S | PERF-C, PERF-N, PERF-O | R | R |
| W02 Browser identity/rendering security | `static/login.js`, `static/enc-key.js`, `static/tt.js` | R | R | R | R | PERF-Q | R | R |
| W03 Browser/native bridge/audio | `static/native-audio.js`, `static/native-bridge.js` | R | R | R | R | PERF-P (native-audio barge-in) | R | R |
| W04 Templates/styles | `static/templates/*`, `static/style.css`, `static/opencode-theme.css` | S | S | S | S | B-PERF-14 retained (visual choice; device cost limit) | B | R |
| W05 Browser state/voice/playback units | `static/session-client.js`, `static/conversation-state.js`, `static/voice-lifecycle.js`, `static/voice-text.js`, `static/voice-events.js`, `static/playback-source.js`, `static/stream-decoder.js`, `static/tts-playback.js`, `static/voice-capture.js`, `static/chat-renderer.js`, `static/credential-crypto.js`, `static/credential-metadata.js`, `static/agent-connections.js`, `static/activity-sync.js` | S | S | S | S | PERF-C, PERF-M, PERF-N, PERF-O, PERF-P | R | R |
| N01 Android identity/activity/logging | `android/app/src/main/java/com/chatbot/app/MainActivity.java`, `android/app/src/main/java/com/chatbot/app/NativeSecureKey/*`, `android/app/src/main/java/com/chatbot/app/Logger/*`, `android/app/src/main/java/com/chatbot/app/util/*` | R | R | R | R | PERF-I (N-PERF-15) | R | R |
| N02 Android voice/audio | `android/app/src/main/java/com/chatbot/app/NativeMic/*`, `android/app/src/main/java/com/chatbot/app/NativeVoiceTts/*`, `android/app/src/main/java/com/chatbot/app/audio/*` | R | R | R | R | PERF-G, PERF-I; N-PERF-1 not implemented (device timing); N-PERF-12/13/14/17 retained | R | R |
| N03 Android Auto | `android/app/src/main/java/com/chatbot/app/car/*` | S | S | S | S | PERF-H; N-PERF-5/6 deferred (user-deferred protocol/transport) | P | P |
| T04 Android tests | `android/app/src/test/*`, `android/app/src/androidTest/*` | R | P | — | P | PERF-G, PERF-H, PERF-I (native regression fixtures) | R | B |
| N04 Android packaging/resources/tooling | `android/*`, `capacitor.config.json` | B | B | — | B | B — APK build gate pending; no packaging performance finding | B | B |
| X01 DNS sidecar (post-baseline) | `dns/*` | — | S | S | S | R — reviewed; no performance finding | R | R |
| G01 GPU voice service | `chatbot-cuda/*` | R | R | R | R | PERF-E, PERF-Q; B-PERF-8 open (host GPU timing); B-PERF-10 retained | P | P |
| O01 CI/automation | `.github/*`, `scripts/*` | R | R | R | R | R — reviewed; no performance finding | R | R |
| O02 Deployment templates | `deploy/*` | R | R | R | R | S-PERF-7 open (host proxy); S-PERF-8 open (COOP/COEP likely inert) | B | R |
| O03 Repository development environment | `.devcontainer/*`, `.grok/*` | B | B | — | B | B — reviewed boundary; no performance finding | B | B |
| D01 Review records | `docs/codebase-review/*` | B | B | — | B | B — Phase 5 record; no application performance finding | R | R |
| D02 Architecture/operator documentation | `docs/*` | B | B | — | B | B — reviewed; no performance finding | R | R |
| R00 Root build/configuration/documentation | Remaining root files (no `/`) | B | B | — | B | B — host-proxy compression open (S-PERF-7); deployment boundary | B | B |

T and D record the scope reviewed in Phase 6 and Phase 7, not a current line-by-line certification. Phase 6 mapped production units to the tests that exercise them and assessed the listed test units for coverage quality; it did not re-audit every assertion, and no line/branch coverage instrumentation was available. `R` therefore means the test boundary was reviewed/mapped, not that every behavior or later candidate is covered. Phase 7 read tracked prose documentation and behavior-describing comment blocks; `P`/`B` retain areas where only partial or boundary-level alignment was established. The PR-001–022 candidate findings and their focused regressions are separate follow-up evidence; they do not retroactively make every historical matrix cell complete or close the findings.

## Assignment, scope and exclusions

Assign each tracked path to the first matching row; comma-separated patterns are alternatives and `*` includes nested paths. R00 covers unmatched repository-root files only. Unmatched new paths require an inventory update. Nested tests/docs stay with their owning component where specified; inline tests stay with source. Before pass completion, expand broad units into file/behavior evidence, resolve unmapped paths, trace cross-component flows and explain exclusions. Assignment is inventory completeness, not review completion.

Protected `.config.yml`, `.env` and runtime `data/` contents are not read without authorization. Ignored caches/runtime trees are outside the source inventory. Vendored/generated/minified code and binaries are not claimed as handwritten-source review; evaluate provenance, integration, distribution and configuration boundaries instead. Executor-side files are outside this repository. Boundary-only units retain their stated limits. Review coverage is not a test-coverage measurement and `R` is not proof of absence.

## Phase completion

- **Phase 1 — [modularity](modularity.md):** complete for handwritten application code and test boundaries; final suite `20260919T202846-0908e2daba66`. No phone, vehicle or GPU runtime validation.
- **Phase 2 — [simplicity](simplicity.md):** complete after SIM-001–012 and review fixes; final suite `20260928T080643-0e0c1b195846` (121 suites / 992 passed, plus 63 embedded Python). Physical-debug APK built.
- **Phase 3 — [abstractions](abstractions.md):** accepted within agreed moderate scope, ABS-001–012; final suite `20260928T225818-53da7826b56a` (122 suites / 997 passed, plus 64 nested Python). Android compiled; JS/DNS/CUDA deployment requires host rebuilds.
- **Phase 4 — [security](security.md):** complete for reviewed scope and accepted exclusions; final suite `20260929T043340-482ba1a11f9d` (1,033 Rust + 64 Python passed). Device/topology limits remain.
- **Phase 5 — [performance](performance.md):** complete; final suite `20261001T052944-8b04233f9f0f` (146 test binaries) and physical-debug APK built. Device/GPU/host-proxy cost limits remain.
- **Phase 6 — [test quality](test-quality.md):** complete with bounded remediation; TEST-001 is fixed and TQ-026 remains recorded only. Final suite `20261003T210405-6ec64fba7bc9` (151 Rust test-result blocks; 1,171 passed, 0 failed; nested DNS 34 and voice 70 Python tests). See phase record for scope limits.
- **Phase 7 — [documentation](documentation.md):** complete; all prose and comment findings are fixed, including DOC-002's cache sweep/zeroization code change. Three completed plans were retired and the ledger condensed. Final suite `20261003T210405-6ec64fba7bc9` (151 Rust test-result blocks; 1,171 passed, 0 failed; nested DNS 34 and voice 70 Python tests).

## Post-refactor review

The [post-refactor report](post-refactor.md#coverage-and-method) records the repository-wide production/integration review at `6c86a98`, including the inspected component boundaries, candidate-focused test review, runtime evidence and remaining exclusions. Its PR-001–022 findings supplement the completed passes, with PR-022 adding the subsequent user-reported oversized-image inference failure and source-traced forwarding gap; this does not retroactively make historical T/D marks assertion-by-assertion or line coverage.

The final integrated gate for the remediation tree passed as job `20261004T061453-813f3ffc3d50`: 153 nonzero Rust test-result blocks, 1,199 passed, 0 failed. Zero-test result blocks are excluded; nested DNS (34) and voice-service (72) Python tests remain separate counts. The later PR-006 closure was verified separately with 49 focused tests; it is not a full-workspace rerun or an assertion-by-assertion coverage measurement. PR-006 is fixed within its admission contract. The report's physical-device/GPU/heap limits remain open and unrelated; neither verification set implies all-findings closure.
