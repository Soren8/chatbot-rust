# Test coverage and quality review (Phase 6)

## Session 086 — scope and method, 2026-10-01

Baseline: `refactor@46b0841` (Phase 5 complete).

### Scope

- Whole-repository T column in [coverage.md](coverage.md): every production unit is mapped to the tests that exercise it, and every test unit (T01–T04, `chatbot-cuda/tests`, `dns/tests`, the Node-vm and JVM fixtures under `chatbot-server/tests/fixtures`) is assessed for quality.
- Priority: **behavioral gaps on risk paths** (chat admission/settlement, history persistence and encryption, authentication/session/remember, privacy policy, voice/TTS token lifecycle), then **brittle or low-value tests** (source-spelling pins, implementation mirrors, sleeps and timing races, shared mutable fixtures), then redundancy.
- Remediation: add missing behavioral tests; replace source-text pins with behavioral assertions where a behavioral seam exists; consolidate redundant tests. Per the program's testing authorization, tests may be modified, consolidated, replaced or removed when the review justifies it, but never changed to make broken application code pass. A test that exposes an application bug becomes a red-first regression with a bounded fix.
- Correctness findings handed over from Phase 5 (SSE UTF-8 split in `openai.rs`/`xai.rs`, the `search.rs:82–83` slicing panic (recorded in Phase 5 as `:220`), the `users.json` read-modify-write race) are in scope as red-first regressions.

### Evidence standard

The executor offers only the `cargo test` workspace suite (Node-vm, JVM fixture and Python tests run from Rust test binaries); no line/branch coverage instrumentation is available. Coverage is therefore a static mapping from each production module's public behavior and failure paths to the tests that exercise them, recorded per unit. Coverage numbers are not claimed. A gap becomes a finding only when a reviewer has read the production path and confirmed no test exercises it. A brittleness finding cites the assertion and the change that would break it without changing behavior.

## Session 086 — inventory (leads)

Four read-only inventories (core, server Rust, browser JS, Python/Android/support) produced leads by name-grep and partial reads; the primary reviewer confirmed the entries marked **confirmed** by reading the production path and searching every test root.

### Confirmed gaps and defects

| ID | Path | Finding | Disposition |
| --- | --- | --- | --- |
| TQ-001 | `dns/tests/*` | The DNS sidecar's unittest suite is never executed: no Rust wrapper, Dockerfile step or workflow runs it (`docker_build.rs` only checks compose/resolver text). `chatbot-cuda/tests` runs via `voice_service_lifecycle.rs`. | Fixed: `dns_sidecar_unit.rs` runs `python3 -m unittest discover` in `dns/` and asserts a non-zero test count (`20261001T173048-181e900e9aff`, 31 Python tests). |
| TQ-002 | `providers/openai.rs:277, 399`, `providers/xai.rs:188` | Each network read is decoded with `from_utf8_lossy`; a codepoint split across reads becomes U+FFFD. No test streams a split codepoint. (Handed over from Phase 5.) | Fixed: `push_utf8`/`flush_utf8` in `providers/mod.rs` carry an incomplete trailing sequence between reads. `provider_sse_utf8.rs` splits `é` across chunks on all three stream paths: red `20261001T173109-3e79dd0b0842`, green `20261002T015806-b4c964c3fa43`. |
| TQ-003 | `search.rs:82–83` | `&result[..8000]` panics when byte 8000 is inside a multibyte character; no long-Unicode search test. (Handed over from Phase 5.) | Fixed: `truncate_search_result` steps back to a char boundary. `search_truncation.rs`: red `20261002T015520-811cbc867b61` (panic at `search.rs:83`), green `20261002T015715-6bd14644e1eb`; unit tests `20261002T015749-0b0355dfa6b3`. |
| TQ-004 | `user_store.rs` `create_user`, `update_user_preferences` | Load→modify→save with no lock shared across per-request `UserStore` instances; concurrent signups/preference writes can lose an update. No concurrency test. (Handed over from Phase 5.) | Fixed: a process-wide lock keyed by the canonical `users.json` path is held across load→modify→save in both writers. `user_store_concurrency.rs` (8 threads × 10 rounds): red `20261001T174413-201db035799d` (account lost in round 0), green `20261002T015821-d8527dd23133`. Cross-process writers remain unlocked; the server is a single process. |
| TQ-005 | `login.rs:92, 109, 152, 370–420, 511–559`, `signup.rs:69–124` | No test asserts any login/remember/forget/signup rejection: wrong password, unknown user, empty fields, bad CSRF, invalid username, duplicate signup. Every login/signup test asserts only 200/302. | Fixed: `auth_rejections.rs` characterizes 13 rejection paths (`20261001T173255-93c3c68c0478`). |

### Leads (unconfirmed; to be read before batching)

- Core negative paths: malformed/truncated sealed blobs (`history/crypto.rs` `open_blob`, media decode), receipt tamper/wrong-owner (`operation_receipt.rs`), Fernet wrong-key/malformed token, migration failure branches, `remember_store` peek/purge helpers, `config.rs` validation rejections.
- Server route branch matrices: chat/regenerate method/model/provider/privacy error statuses, `sets.rs` per-handler validation, `generations.rs` unknown/foreign-generation status/events/stop, `idempotency.rs` malformed header, Brave HTTP failure parsing.
- Browser JS: `tt.js`, `native-bridge.js`, `agent-connections.js` and `native-audio.js` have no executed test (the latter only source pins); `login.js` partially executed via `sec008_browser_ui.js`.
- Android: `NativeSecureKeyPlugin`/`CredentialCookies` app-level paths, `VoiceAudioRoute` focus denial (fake always grants), `OggOpusStreamDecoder` malformed input, `TtsBodyInputStream` errors. Gradle unit tests under `android/app/src/test` run only in the APK artifact build, not in CI.
- Python: `chatbot-cuda/src/audio_utils.py` ffmpeg failure/cleanup untested; DNS `_recvn` partial reads.

### Quality leads

- Wall-clock waits: `edit_message.rs:375` (100 ms), `tts.rs:1367` (300 ms), `client_logs_session_sweep.rs:62` (`TIMEOUT_SECS + 1`), `server_owned_generations.rs:184` and `auth_hash_offload.rs:70` (polling), `agent_connections.rs:375`; Python lifecycle tests use fixed sleeps/deadlines; DNS `main()` smoke test leaks a serve thread and mutates `threading.excepthook`.
- Not timing-sensitive: the 5 ms sleeps at `chat_session_isolation.rs:130` and `generation_lease_ownership.rs:91,123` follow a zero lease timeout, so expiry is already past and they cannot flake.
- Source-text pins: five pure source-pin files (`android_volume.rs`, `client_log_reporting.rs`, `docker_build.rs`, `native_audio_wav.rs`, `voice_mode_reliability.rs`) plus pins mixed into behavioral files (`stt.rs:478–495`, `home.rs:530–550`, `conversation_state.rs`, `credential_*.rs`, `playback_source_*.rs`, `voice_*_boundary.rs`). Many duplicate an existing Node-vm behavioral fixture; others are the only check on `chat.js` wiring.
- Process-global state: per-binary `test_mutex()` plus `TestWorkspace` env/cwd mutation; `TestWorkspace` drop does not reset global config/rate limits.
- Oversized scenarios: `sets.rs::set_management_flow`, `server_owned_generations.rs:238–340`.
