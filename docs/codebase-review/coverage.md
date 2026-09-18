# Review coverage

Baseline: `4cda3039d3e5a58932a3c40afccc1e4ce33a19e3` (2026-09-16). This is a scoped review ledger, not a test coverage measurement.

Session 001 inventory verification assigned all 288 baseline tracked paths, plus the four new review records, to 35 units with no unassigned paths. Assignment is inventory completeness, not review completion.

## Assignment and status rules

Assign each tracked path to the first matching row below. Comma-separated patterns are alternatives; `*` matches any suffix, including nested paths. R00 matches remaining repository-root files only. Unmatched new paths require an explicit inventory update. Nested tests and docs remain with their owning component where specified; the documentation and testing passes still apply to those units. Inline tests stay with their source file.

Status: `—` not reviewed; `P` partially reviewed, with exact scope below; `R` reviewed for that pass at the baseline revision. `R` does not mean issue-free or fixed. Use `S` for stale coverage after relevant changes. An inapplicable cell requires a recorded reason, not an unexplained blank.

`B` means boundary/integration review only, for non-application or protected/generated/vendor material; its limitations are explicit below. Session 002 advances modularity at `7dc8a23` (same application source as the baseline). The other six columns deliberately receive no completion credit from incidental findings. Test-body coverage is recorded separately from production-code review; uninspected assertions do not count as reviewed tests.

Columns: M modularity; S simplicity; A abstractions/reuse/duplication; Sec security/privacy; Perf performance/resources; T tests; D documentation.

| Unit | Owned paths, in matching order | M | S | A | Sec | Perf | T | D |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| V01 Third-party browser dependencies | `static/deps/*` | B | — | — | — | — | — | — |
| R01 Rust composition | `Cargo.toml`, `chatbot-core/Cargo.toml`, `chatbot-core/src/lib.rs`, `chatbot-server/Cargo.toml`, `chatbot-server/src/lib.rs`, `chatbot-server/src/main.rs`, `chatbot-server/src/background.rs`, `chatbot-server/src/http_error.rs`, `chatbot-server/src/test_instrumentation.rs`, `chatbot-test-support/Cargo.toml` | R | — | — | — | — | — | — |
| C01 Configuration/logging | `chatbot-core/src/config.rs`, `chatbot-core/src/logging.rs` | R | — | — | — | — | — | — |
| C02 Session state/orchestration | `chatbot-core/src/session.rs` | R | — | — | — | — | — | — |
| C03 Identity/key stores | `chatbot-core/src/user_store.rs`, `chatbot-core/src/remember_store.rs`, `chatbot-core/src/enc_key.rs` | R | — | — | — | — | — | — |
| C04 Durable history | `chatbot-core/src/history/*` | R | — | — | — | — | — | — |
| C05 Persistence/legacy migration | `chatbot-core/src/persistence.rs`, `chatbot-core/src/legacy_sets_json/*` | R | — | — | — | — | — | — |
| C06 Chat content/images | `chatbot-core/src/chat.rs`, `chatbot-core/src/chat_images.rs` | R | — | — | — | — | — | — |
| C07 Core rate limiting | `chatbot-core/src/rate_limit.rs` | R | — | — | — | — | — | — |
| C08 Shared naming/Fernet helpers | `chatbot-core/src/names.rs`, `chatbot-core/src/fernet_crypto.rs` | R | — | — | — | — | — | — |
| T01 Core integration tests | `chatbot-core/tests/*` | R | — | — | — | — | — | — |
| S01 Chat streaming/orchestration | `chatbot-server/src/chat.rs`, `chatbot-server/src/chat_utils.rs`, `chatbot-server/src/regenerate.rs` | R | — | — | — | — | — | — |
| S02 Authentication/home | `chatbot-server/src/home.rs`, `chatbot-server/src/login.rs`, `chatbot-server/src/logout.rs`, `chatbot-server/src/signup.rs` | R | — | — | — | — | — | — |
| S03 History/memory/preferences routes | `chatbot-server/src/sets.rs`, `chatbot-server/src/memory.rs`, `chatbot-server/src/preferences.rs`, `chatbot-server/src/reset_chat.rs` | R | — | — | — | — | — | — |
| S04 Providers/search/tools | `chatbot-server/src/providers/*`, `chatbot-server/src/brave.rs`, `chatbot-server/src/search.rs`, `chatbot-server/src/tools.rs` | R | — | — | — | — | — | — |
| S05 Voice endpoints/codecs | `chatbot-server/src/stt.rs`, `chatbot-server/src/tts.rs`, `chatbot-server/src/tts_opus.rs` | R | — | — | — | — | — | — |
| S08 Speech-text normalization | `chatbot-server/src/tts/text.rs` | R | — | — | — | — | — | — |
| S09 TTS backend synthesis | `chatbot-server/src/tts/backend.rs` | R | — | — | — | — | — | — |
| S10 TTS token-session store | `chatbot-server/src/tts/store.rs` | R | — | — | — | — | — | — |
| S06 Operational endpoints/limits | `chatbot-server/src/health.rs`, `chatbot-server/src/client_logs.rs`, `chatbot-server/src/rate_limit_middleware.rs` | R | — | — | — | — | — | — |
| T02 Server integration tests/fixtures | `chatbot-server/tests/*` | R | — | — | — | — | — | — |
| T03 Shared test support | `chatbot-test-support/src/*` | R | — | — | — | — | — | — |
| S07 Server examples/protected configuration | `chatbot-server/examples/*`, `chatbot-server/.config.yml` | B | — | — | — | — | — | — |
| W01 Browser chat UI | `static/chat.js` | R | — | — | — | — | — | — |
| W02 Browser identity/rendering security | `static/login.js`, `static/enc-key.js`, `static/tt.js` | R | — | — | — | — | — | — |
| W03 Browser/native bridge/audio | `static/native-audio.js`, `static/native-bridge.js` | R | — | — | — | — | — | — |
| W04 Templates/styles | `static/templates/*`, `static/style.css` | R | — | — | — | — | — | — |
| N01 Android identity/activity/logging | `android/app/src/main/java/com/chatbot/app/MainActivity.java`, `android/app/src/main/java/com/chatbot/app/NativeSecureKey/*`, `android/app/src/main/java/com/chatbot/app/Logger/*`, `android/app/src/main/java/com/chatbot/app/util/*` | R | — | — | — | — | — | — |
| N02 Android voice/audio | `android/app/src/main/java/com/chatbot/app/NativeMic/*`, `android/app/src/main/java/com/chatbot/app/NativeVoiceTts/*`, `android/app/src/main/java/com/chatbot/app/audio/*` | R | — | — | — | — | — | — |
| N03 Android Auto | `android/app/src/main/java/com/chatbot/app/car/*` | R | — | — | — | — | — | — |
| T04 Android tests | `android/app/src/test/*`, `android/app/src/androidTest/*` | R | — | — | — | — | — | — |
| N04 Android packaging/resources/tooling | `android/*`, `capacitor.config.json` | B | — | — | — | — | — | — |
| G01 GPU voice service | `chatbot-cuda/*` | R | — | — | — | — | — | — |
| O01 CI/automation | `.github/*`, `scripts/*` | R | — | — | — | — | — | — |
| O02 Deployment templates | `deploy/*` | R | — | — | — | — | — | — |
| O03 Repository development environment | `.devcontainer/*`, `.grok/*` | B | — | — | — | — | — | — |
| D01 Review records | `docs/codebase-review/*` | B | — | — | — | — | — | — |
| D02 Architecture/operator documentation | `docs/*` | B | — | — | — | — | — | — |
| R00 Root build/configuration/documentation | Remaining root files (no `/`) | B | — | — | — | — | — | — |

## Session 001 read evidence and limitations

All R01 files were read in full. Review covered workspace dependency direction, exports, startup/task ownership, route assembly, inline middleware, and error conversion. Handler authorization correctness, middleware runtime behavior, background execution performance, and all transitive dependencies remain for their owning units/passes. Findings MOD-001/MOD-002 cross the composition boundary into partially reviewed C02.

Supporting reads (not whole-unit completion):

| Unit | Precisely inspected scope |
| --- | --- |
| C01 | `config.rs:124–217`: configuration model, global accessor, reset |
| C02 | `session.rs:1–739,760–1057`: HTTP sessions, chat store, response/key helpers, chat prepare/finalize; symbol listing for the rest is navigation only |
| C04 | `history/api.rs:1–120`: error types, lock declarations, service/global entry |
| S01 | `chat.rs:1–230`: input, identity, provider selection, preparation and start of provider construction |
| S02 | `home.rs` in full; other files unread |
| T03 | `src/lib.rs` in full as dependency/lifecycle context; callers and test-quality evaluation not yet reviewed |
| D02 | `docs/design.md` and `docs/design-privacy.md` read as orientation, not validated against all implementation claims; no pass credit |

Searches for `ServiceResponse`/`build_response` consumers located follow-up sites in chat utilities and state-mutating routes; a matching line does not count as reading those files.

## Special handling

Protected `.config.yml`, `.env`, and runtime `data/` contents are not read without explicit authorization. `chatbot-server/.config.yml` and `.devcontainer/stubs/.env` are inventoried by path only. Review public examples, parsers, and mounting/build rules; record any resulting coverage limitation rather than requesting live secrets. Ignored caches/runtime trees are outside the source inventory.

Vendored browser libraries, model/WASM/font/image binaries, and the Gradle wrapper JAR require provenance/version, integration, distribution, and configuration review. Do not claim handwritten-source review of generated/minified or binary artifacts. Generated Gradle/Capacitor and IDE files require ownership/generation-path evaluation before any edits. Root lockfiles require dependency review, not line-by-line application logic review.

Before declaring a pass complete, expand broad units into file/behavior-level evidence as they are read, resolve unmapped paths, trace the cross-component flows, and explicitly explain exclusions. A single representative file does not complete a directory-sized unit.

## Session 002 production-code coverage

All handwritten production Rust implementation under `chatbot-core/src/` and `chatbot-server/src/` has been read across sessions 001–002, including production functions that occur after an inline test module (`tts.rs:1488–1610`). Rust inline test modules were inspected selectively for setup/dependency boundaries rather than exhaustively audited assertion by assertion. The separate server integration tree and Android test files were subsequently read through for modularity. The testing pass remains unstarted: a structural review is not a systematic behavior-coverage/quality audit.

| Units | Read scope and modularity conclusion |
| --- | --- |
| C01 | `config.rs:1–855` and `logging.rs` in full: resolution/validation stays together, but ambient configuration has multiple consumers/initialization lifetimes (MOD-003/015/017) |
| C02 | `session.rs` in full: identity, working state, prepare/finalize, mutation APIs and guards traced through server callers (MOD-001/002/006) |
| C03 | `user_store.rs`, `enc_key.rs` in full; `remember_store.rs:1–451` plus test fixture/initial cases through 560: store/error/key boundaries, cookie-policy overlap and concurrency lead recorded |
| C04 | Every production section in `history/{mod,api,cache,crypto,migration,ops,types}.rs` and `history/store/{mod,chunks,keys,tables}.rs`: private durable store is retained; representation/escape-hatch findings in MOD-005 |
| C05 | `persistence.rs` and all three `legacy_sets_json` files: migration remains necessary; live helpers point back into its format store (MOD-004) |
| C06 | `chat.rs:1–296` and `chat_images.rs:1–653`, with initial inline-test fixtures: pure packing exists but input ownership and image representations cross responsibilities |
| C07, T01 | `rate_limit.rs` and `tests/user_store_atomicity.rs` in full: isolated limiter algorithm behind a global entry, atomic-write versus transaction distinction |
| S01–S03 | All listed files in full: generation, auth/cookie, and durable-mutation chains traced; MOD-006/007/008 |
| S04 | `providers/mod.rs`, `message_utils.rs`, `brave.rs`, `search.rs`, `tools.rs` in full; OpenAI through 754 and XAI through 312: concrete dispatch and shared OpenAI DTO ownership |
| S05–S06 | All production sections in all six files: TTS token/text/backend/HTTP ownership, codec seam, STT forwarding, health, log ingest and limiter integration |
| T03 | Entire shared fixture crate: global cwd/env setup, cleanup and helper ownership; independent application construction is absent |
| W01–W04 | All six first-party JS files, all three templates and all 984 CSS lines: global initialization/state, DOM-driven playback, parser duplication, bridge boundaries and page-scoped styling evaluated |
| N01–N03 | All 20 production Java files in these units read in full: activity/key/logging, microphone/playback, audio helpers, Auto lifecycle and transport |
| T04 | All six local/instrumented Java test files read in full: small policy collaborators are testable; template tests and missing adapter/device coverage are later-pass leads |
| G01 | All Python source, requirements, Dockerfile and startup script: HTTP/model/audio separation exists; configuration/readiness/thread lifetimes remain ambient |
| O01–O02 | Every workflow, automation script, CodeQL/Dependabot config and all Compose/Helm sample files read: separate test/publish/scan jobs, partial deployment topology and external voice-service ownership |

### Boundary-only units and explicit exclusions

V01: reviewed `static/deps/README.md`, `vad/VERSION`, script/asset loading in templates and JS, and CSP ownership. Vendored/minified implementations and binary payloads were not line-audited or provenance-verified. Dependency vulnerability/provenance checks belong to the security pass.

S07: read the full offline Opus fixture example and its production-module include; protected `.config.yml` content remains excluded. Its existence does not certify provider configuration.

N04: read the APK build script, Gradle manifests/settings/variables/properties/generated includes, ProGuard file, Capacitor config, AndroidManifest, activity layout, strings/styles/arrays, security/file-provider/Auto XML, and wrapper distribution metadata. Launcher/splash artwork, IDE project files and standard generated wrapper scripts/JAR were inventoried, not source-audited. Packaging references were evaluated; no APK was built.

O03: read every development-environment Dockerfile, launcher, reusable-template script/JSON, README, overlay-verification script and `.grok/sandbox.toml`. Stub secret/data contents remain excluded. No script was executed and the current host/sandbox setup was not inspected or altered.

D01/D02: review records and architecture/privacy/history/mobile/audio/TTS documents were consulted for boundaries and intended contracts. Mobile document read through 380; both history design documents read through the end (the tools truncate very long individual lines). These are not a complete documentation-accuracy audit. R00: root Docker/Compose/toolchain/public config/examples/README/ignore/attribute/instruction entry points read; Cargo.lock is inventoried as generated resolution metadata, not an independently audited dependency graph.

## Session 002 test-boundary evidence

The full server test tree's imports, top-level helpers and suite structure were surveyed, then all 44 Rust files (including `common/mod.rs`) and four executable fixtures were read through for modularity. Searches were navigation evidence only. Production globals and fixture seams were traced through concrete test bodies. This is not completion of the separate quality/coverage pass or a claim that these tests currently pass.

Review first covered `common/mod.rs`, `session_purge.rs`, `client_logs.rs`, `client_log_reporting.rs`, `docker_build.rs`, `js_syntax.rs`, `native_audio_wav.rs`, `native_vad_speech_like.rs`, `voice_mode_reliability.rs`, `tts_download_queue.rs`, `tts_sentence_boundaries.rs`, `static_assets.rs`, `search.rs`, `rate_limit.rs`, `http_errors.rs`, and all four files in `fixtures/`.

Review then completed the remaining HTTP files: `chat`, `regenerate`, `edit_message`, `load_set_history`, `history_robustness`, `enc_key_auth`, `login`, `remember_login`, `stt`, `tts`, `sets_auth`, `csp`, `expired_session`, `expired_session_save`, `health`, `reset_chat`, `preferences`, `client_derivation`, `signup`, `ip_extraction`, `set_privacy`, `memory_limit`, `logout`, `delete_message`, `fork_set`, `csrf_bypass`, `home`, `sets`, and `memory` (all `.rs`).

Relevant seams: duplicated login/bootstrap/cookie helpers and raw users.json seeds; globals/env-based fake providers; captured local HTTP voice stubs; separate per-file mutexes; source-extracted JS and cross-language algorithm copies; direct core session/history calls from HTTP tests. Useful existing behavior includes captured-set conflicts, preserving later turns on regenerate, stop-then-edit, key gates, token replay/cancel and ordered downloads. Findings MOD-003/006/016 and TEST-001–005 record issues without discarding those regressions.

## Modularity pass disposition

The first architectural/modularity pass is complete for handwritten application code and test boundaries, with the seven `B` units explicitly limited to integration/packaging/document interfaces. No dependency binary, protected runtime config, live deployment, GPU execution or on-device behavior is certified. The six later passes remain open and will inspect their own criteria independently. No structural remediation has been implemented yet.

Final inventory check: all 293 tracked paths (288 application-baseline paths plus five review records) map to 35 units: 28 reviewed and seven boundary-only. The MOD-001–017 definitions are unique and consecutive; relative review-document links resolve. Only the five review documents are staged, and application/test/configuration trees match the application baseline. Diff whitespace checks pass. No application test execution is implied by these checks.

## Session 003 remediation coverage

The table now includes C08 and S08 for the extracted modules; the new `chatbot-core/tests/live_helper_contracts.rs` belongs to T01. The inventory grows to 297 paths in 37 units (30 `R`, seven `B`). These additions do not advance the six later review passes.

Modularity coverage for R01, C02–C05, T01, S03 and S05 was stale during implementation and was revalidated for the changed naming/Fernet/TTS boundaries through primary source/diff review and the passing full suite. The primary read both new core modules and their tests; verified the exact TTS regex/helper/test relocation against `9b2624b`; reviewed legacy compatibility/error adapters, session/history callers and memory/reset HTTP mappings; and checked that live server/session paths no longer import legacy persistence helpers. C08/S08 are reviewed at the remediation commit recorded in README. Other units retain their baseline review scope; unchanged files were not exhaustively re-audited. D01/D02 remain boundary-only despite the targeted documentation updates.

Runtime evidence is now available for this batch: baseline job `20260916T161549-8201e4a67090` and final job `20260916T163326-652a9002d614` passed the full executor suite. This supersedes the earlier no-remediation/no-test-execution statement only for session 003, not the original static review.

## Session 004 remediation coverage

The new `static/stream-decoder.js` belongs to W01; the new `chatbot-server/tests/stream_decoder.rs` and `chatbot-server/tests/fixtures/stream_decoder_test.js` belong to T02. The inventory grows to 300 paths in 37 units (30 `R`, seven `B`). These additions do not advance the six later review passes.

Modularity coverage for W01 and T02 was stale during implementation and was revalidated for the changed stream-decoder boundaries through source/diff review and the passing full suite. The worker read the three browser parsers, server encoders and wire/test coverage; verified the shared tag/hold/console logic against the original loops; reviewed the explicit chat/regenerate/history adapters and template load order; and checked that no existing tests were modified. W01/T02 deltas are reviewed at the remediation commit recorded in README. Other units retain their prior scope; unchanged files were not exhaustively re-audited. D01/D02 remain boundary-only despite the targeted documentation updates.

Runtime evidence for this batch: baseline job `20260916T175420-4b7dbb22aa88` passed with the new decoder plus characterization and original chat wiring untouched; the mixed-order regression failed as expected in job `20260916T180645-05a6588a814b` (`status=failed`, exit 101); the corrected wired implementation passed in final job `20260916T181236-a3251f9db599` (`status=passed`, exit 0). The earlier wired green job `20260916T180042-78771ee26d7f` is superseded: its assertions checked joined text only, not callback order.

## Session 005 remediation coverage

The new `chatbot-server/src/tts/backend.rs` belongs to S09; the new `chatbot-server/tests/tts_backend_boundary.rs` belongs to T02. The inventory grows to 302 paths in 38 units (31 `R`, seven `B`). These additions do not advance the six later review passes.

Modularity coverage for S05 and T02 was stale during implementation and was revalidated for the changed TTS backend boundary through source/diff review and the passing full suite. The worker personally read the synthesis/HTTP flow, callers, error mappings and existing TTS tests; kept token lifetime, access policy, codec conversion and HTTP rendering in the parent; moved provider requests, the shared client, fade, WAV parsing, silence and error helpers narrowly with statuses/messages/log contexts preserved; and kept the encoded-size rejection status/message with retry reset via an explicit post-encode check. S09/T02 deltas are reviewed at the remediation commit recorded in README. Other units retain their prior scope; unchanged files were not exhaustively re-audited. D01/D02 remain boundary-only despite the targeted documentation updates.

## Session 006 remediation coverage

The new `chatbot-server/src/tts/store.rs` belongs to S10. The inventory grows to 303 paths in 39 units (32 `R`, seven `B`). These additions do not advance the six later review passes.

Modularity coverage for S05 was stale during implementation and was revalidated for the changed TTS token-store boundary through source/diff review and the passing full suite. The worker read the token/HTTP flow, callers, error mappings and existing TTS tests; moved the wire-audio type, pending entries, TTL/cap/replay policy, prune/eviction helpers, cancel and the generation guard narrowly into the owned store with statuses/messages/headers/log contexts preserved; kept one global parent store plus minting, access policy, codec conversion, the encoded-size rejection with retry reset, and HTTP rendering; and preserved token-collision overwrite rather than fixing it. S10 deltas are reviewed at the remediation commit recorded in README. Other units retain their prior scope; unchanged files were not exhaustively re-audited. D01/D02 remain boundary-only despite the targeted documentation updates.

## Session 007 remediation coverage

The new `chatbot-server/src/providers/generation.rs` belongs to S04; the new `chatbot-server/tests/generation_dispatch.rs` belongs to T02. The inventory grows to 305 paths in 39 units (32 `R`, seven `B`). These additions do not advance the six later review passes.

Modularity coverage for S01, S04 and T02 was stale during implementation and was revalidated for the changed generation-dispatch boundary through source/diff review and the passing full suite. The worker read both handlers, all provider/search/brave/tool modules and the existing chat/regenerate/search/history seams; moved the closed provider enum, provider construction with provider-specific error strings, core-to-DTO mapping and search-gated streaming narrowly into the shared module with gating/warnings/timing preserved; kept validation, saved-turn rendering with append-versus-replace, user-text selection, guards/finalizers and response building in the handlers; and kept the existing OpenAI-owned DTO without a trait hierarchy. S04/T02 deltas are reviewed at the remediation commit recorded in README. Other units retain their prior scope; unchanged files were not exhaustively re-audited. D01/D02 remain boundary-only despite the targeted documentation updates.

## Session 008 remediation coverage

Session 012 adds `chatbot-server/tests/prepare_validation_boundary.rs` to T02 (311 tracked paths). Primary reviewed core prepare validation, both handlers and the HTTP mapper; ten new router tests pass before and after extraction. Broader session lifetimes and core service outcomes retain their open dispositions.

Session 011 adds `chatbot-server/tests/enc_key_validation_boundary.rs` to T02 (310 tracked paths). Targeted review covers the typed validator in core session, its compatibility adapter, direct server mappings and seven new behavioral tests. Pre-extraction characterization and corrected full-suite verification passed; broader core and HTTP boundaries retain their earlier dispositions.

Session 010 changes only existing C04 history implementation files (`api.rs`, `cache.rs`, `mod.rs`); the inventory remains 309 paths. Caller/export inventory and primary diff review revalidated this narrowed facade, supported by baseline/final full-suite passes. No tests were modified. Other units retain their previous coverage.

Session 009 adds `chatbot-server/src/enc_key_cookies.rs` to the server request boundary and `chatbot-server/tests/enc_key_cookies_boundary.rs` to T02, bringing the tracked inventory to 309 paths. Targeted primary review covered the verbatim extraction, compatibility exports and new behavioral tests; baseline/final full suites passed. Unchanged units retain their prior review scope.

The new `chatbot-server/src/providers/messages.rs` belongs to S04; the new `chatbot-server/tests/provider_messages.rs` belongs to T02. The inventory grows to 307 paths in 39 units (32 `R`, seven `B`). These additions do not advance the six later review passes.

Modularity coverage for S04 and T02 was stale during implementation and was revalidated for the changed message-ownership boundary through source/diff review and the passing full suite. The worker inventoried every `openai::messages` consumer, moved the shared types and constructors verbatim into the neutral module, migrated all production imports, kept `openai::messages` as a re-export, preserved serialization/constructors/images/tool-call/`None` omission and the XAI mapping with no trait or schema redesign, and corrected the trait-based provider abstraction claim in `docs/design.md` to the concrete enum dispatch. S04/T02 deltas are reviewed at the remediation commit recorded in README. Other units retain their prior scope; unchanged files were not exhaustively re-audited. D01/D02 remain boundary-only despite the targeted documentation updates.
