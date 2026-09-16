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
| T01 Core integration tests | `chatbot-core/tests/*` | R | — | — | — | — | — | — |
| S01 Chat streaming/orchestration | `chatbot-server/src/chat.rs`, `chatbot-server/src/chat_utils.rs`, `chatbot-server/src/regenerate.rs` | R | — | — | — | — | — | — |
| S02 Authentication/home | `chatbot-server/src/home.rs`, `chatbot-server/src/login.rs`, `chatbot-server/src/logout.rs`, `chatbot-server/src/signup.rs` | R | — | — | — | — | — | — |
| S03 History/memory/preferences routes | `chatbot-server/src/sets.rs`, `chatbot-server/src/memory.rs`, `chatbot-server/src/preferences.rs`, `chatbot-server/src/reset_chat.rs` | R | — | — | — | — | — | — |
| S04 Providers/search/tools | `chatbot-server/src/providers/*`, `chatbot-server/src/brave.rs`, `chatbot-server/src/search.rs`, `chatbot-server/src/tools.rs` | R | — | — | — | — | — | — |
| S05 Voice endpoints/codecs | `chatbot-server/src/stt.rs`, `chatbot-server/src/tts.rs`, `chatbot-server/src/tts_opus.rs` | R | — | — | — | — | — | — |
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
