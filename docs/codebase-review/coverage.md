# Review coverage

Baseline: `4cda3039d3e5a58932a3c40afccc1e4ce33a19e3` (2026-09-16). This is a scoped review ledger, not a test coverage measurement.

Session 001 inventory verification assigned all 288 baseline tracked paths, plus the four new review records, to 35 units with no unassigned paths. Assignment is inventory completeness, not review completion.

## Assignment and status rules

Assign each tracked path to the first matching row below. Comma-separated patterns are alternatives; `*` matches any suffix, including nested paths. R00 matches remaining repository-root files only. Unmatched new paths require an explicit inventory update. Nested tests and docs remain with their owning component where specified; the documentation and testing passes still apply to those units. Inline tests stay with their source file.

Status: `—` not reviewed; `P` partially reviewed, with exact scope below; `R` reviewed for that pass at the baseline revision. `R` does not mean issue-free or fixed. Use `S` for stale coverage after relevant changes. An inapplicable cell requires a recorded reason, not an unexplained blank.

Columns: M modularity; S simplicity; A abstractions/reuse/duplication; Sec security/privacy; Perf performance/resources; T tests; D documentation.

| Unit | Owned paths, in matching order | M | S | A | Sec | Perf | T | D |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| V01 Third-party browser dependencies | `static/deps/*` | — | — | — | — | — | — | — |
| R01 Rust composition | `Cargo.toml`, `chatbot-core/Cargo.toml`, `chatbot-core/src/lib.rs`, `chatbot-server/Cargo.toml`, `chatbot-server/src/lib.rs`, `chatbot-server/src/main.rs`, `chatbot-server/src/background.rs`, `chatbot-server/src/http_error.rs`, `chatbot-server/src/test_instrumentation.rs`, `chatbot-test-support/Cargo.toml` | R | — | — | — | — | — | — |
| C01 Configuration/logging | `chatbot-core/src/config.rs`, `chatbot-core/src/logging.rs` | P | — | — | — | — | — | — |
| C02 Session state/orchestration | `chatbot-core/src/session.rs` | P | — | — | — | — | — | — |
| C03 Identity/key stores | `chatbot-core/src/user_store.rs`, `chatbot-core/src/remember_store.rs`, `chatbot-core/src/enc_key.rs` | — | — | — | — | — | — | — |
| C04 Durable history | `chatbot-core/src/history/*` | P | — | — | — | — | — | — |
| C05 Persistence/legacy migration | `chatbot-core/src/persistence.rs`, `chatbot-core/src/legacy_sets_json/*` | — | — | — | — | — | — | — |
| C06 Chat content/images | `chatbot-core/src/chat.rs`, `chatbot-core/src/chat_images.rs` | — | — | — | — | — | — | — |
| C07 Core rate limiting | `chatbot-core/src/rate_limit.rs` | — | — | — | — | — | — | — |
| T01 Core integration tests | `chatbot-core/tests/*` | — | — | — | — | — | — | — |
| S01 Chat streaming/orchestration | `chatbot-server/src/chat.rs`, `chatbot-server/src/chat_utils.rs`, `chatbot-server/src/regenerate.rs` | P | — | — | — | — | — | — |
| S02 Authentication/home | `chatbot-server/src/home.rs`, `chatbot-server/src/login.rs`, `chatbot-server/src/logout.rs`, `chatbot-server/src/signup.rs` | P | — | — | — | — | — | — |
| S03 History/memory/preferences routes | `chatbot-server/src/sets.rs`, `chatbot-server/src/memory.rs`, `chatbot-server/src/preferences.rs`, `chatbot-server/src/reset_chat.rs` | — | — | — | — | — | — | — |
| S04 Providers/search/tools | `chatbot-server/src/providers/*`, `chatbot-server/src/brave.rs`, `chatbot-server/src/search.rs`, `chatbot-server/src/tools.rs` | — | — | — | — | — | — | — |
| S05 Voice endpoints/codecs | `chatbot-server/src/stt.rs`, `chatbot-server/src/tts.rs`, `chatbot-server/src/tts_opus.rs` | — | — | — | — | — | — | — |
| S06 Operational endpoints/limits | `chatbot-server/src/health.rs`, `chatbot-server/src/client_logs.rs`, `chatbot-server/src/rate_limit_middleware.rs` | — | — | — | — | — | — | — |
| T02 Server integration tests/fixtures | `chatbot-server/tests/*` | — | — | — | — | — | — | — |
| T03 Shared test support | `chatbot-test-support/src/*` | P | — | — | — | — | — | — |
| S07 Server examples/protected configuration | `chatbot-server/examples/*`, `chatbot-server/.config.yml` | — | — | — | — | — | — | — |
| W01 Browser chat UI | `static/chat.js` | — | — | — | — | — | — | — |
| W02 Browser identity/rendering security | `static/login.js`, `static/enc-key.js`, `static/tt.js` | — | — | — | — | — | — | — |
| W03 Browser/native bridge/audio | `static/native-audio.js`, `static/native-bridge.js` | — | — | — | — | — | — | — |
| W04 Templates/styles | `static/templates/*`, `static/style.css` | — | — | — | — | — | — | — |
| N01 Android identity/activity/logging | `android/app/src/main/java/com/chatbot/app/MainActivity.java`, `android/app/src/main/java/com/chatbot/app/NativeSecureKey/*`, `android/app/src/main/java/com/chatbot/app/Logger/*`, `android/app/src/main/java/com/chatbot/app/util/*` | — | — | — | — | — | — | — |
| N02 Android voice/audio | `android/app/src/main/java/com/chatbot/app/NativeMic/*`, `android/app/src/main/java/com/chatbot/app/NativeVoiceTts/*`, `android/app/src/main/java/com/chatbot/app/audio/*` | — | — | — | — | — | — | — |
| N03 Android Auto | `android/app/src/main/java/com/chatbot/app/car/*` | — | — | — | — | — | — | — |
| T04 Android tests | `android/app/src/test/*`, `android/app/src/androidTest/*` | — | — | — | — | — | — | — |
| N04 Android packaging/resources/tooling | `android/*`, `capacitor.config.json` | — | — | — | — | — | — | — |
| G01 GPU voice service | `chatbot-cuda/*` | — | — | — | — | — | — | — |
| O01 CI/automation | `.github/*`, `scripts/*` | — | — | — | — | — | — | — |
| O02 Deployment templates | `deploy/*` | — | — | — | — | — | — | — |
| O03 Repository development environment | `.devcontainer/*`, `.grok/*` | — | — | — | — | — | — | — |
| D01 Review records | `docs/codebase-review/*` | — | — | — | — | — | — | — |
| D02 Architecture/operator documentation | `docs/*` | — | — | — | — | — | — | — |
| R00 Root build/configuration/documentation | Remaining root files (no `/`) | — | — | — | — | — | — | — |

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
