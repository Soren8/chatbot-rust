# Abstractions / reuse / duplication review (Phase 3)

Scope (user-authorized): fresh repository-wide inventory, moderate bounded fixes with zero behavior change. Deferred items (COR-003, Auto protocol repair, legacy key export) stay out unless the duplication itself is in the touched code. Each batch carries targeted verification plus a final full green suite.

## Phase 3 closure (sessions 063–072) — ready for review

Full reads now cover every handwritten unit (sessions 068 + 070 + 072 below give per-file line ranges; no skim stands without a recorded follow-up). The A column uses R where every owned file received a full abstraction read, P with exact scope elsewhere; R does not mean issue-free.

Implemented (all zero-behavior-change, targeted-green): ABS-001 DNS filtering + preflight; ABS-002 prepare-error + mutation-error mappers; ABS-003 media AAD + snapshot assembly + first-turn naming (2 new assertions); ABS-004 OpenAI setup + CSRF builder + base64 decoder; ABS-005 image-edit skeleton + constant-time-eq centralization (1 new direct test); ABS-006 page-response builder + agent guard prefixes + request-context fallback sharing; ABS-007 Kokoro warmup sharing (1 new characterization test); ABS-008 login-notice setter + desktop retry-decision sharing (1 new Node characterization target) and Android origin delegation with a javac-executed behavior fixture plus migrated guard assertions.

Final full suite `temp/test-logs/abs009-full-20260928.log`: job `20260928T225818-53da7826b56a`, exit 0, untruncated, 122 suites ok / 997 passed / 0 failed (plus 64 nested Python), including provider configuration checks. JS/DNS/CUDA changes need host rebuilds to deploy; Android compiles under the session-071 physical-debug build (72 tasks).

Deferred with concrete technical rationale (prerequisites stated, not bare labels): `session.rs` mirror-pair merge (post-durable/mismatch control-flow risk); secure-flag choice sharing (per-caller config-read timing); coordinator release extraction (caller-specific async release ordering; needs ordering tests); complete-clip read merge (WAV/Opus validation + error text differ on the voice-reliability path; needs paired chunking/truncation/cancellation cases); button-style setup (no view assertions in gate; cosmetic); `ClientLogReporter` origin handling (distinct logging/null-on-error contract); cross-runtime mirrors — voice-text vs TTS text, cookie transport, PCM rate (separate stages/runtimes); `legacy_sets_json` setters (no direct setter coverage); COR-003/Auto protocol/key export (owning passes).

## Session 063 — fresh duplication inventory, 2026-09-28

Four parallel subagents inventoried exclusive partitions at `refactor@f4ca399`; primary synthesized. No edits in this session.

### Core (`chatbot-core/src`)
- CANDIDATE: first-turn auto-naming duplicated across two append paths (`history/api.rs:713–732`, `749–771`) — needs naming-outcome assertions on both paths before dedup.
- CANDIDATE: memory/prompt mirror pairs (`session.rs:1800–1848`, `2086–2163`) — share identical steps only, retain durable-before-mirror and mismatch semantics; needs parity assertions first.
- CANDIDATE: media AAD builders differing only by domain label (`history/crypto.rs:158–180`) — label-parameterized private builder; crypto round-trip tests at `history/crypto.rs:621`.
- CANDIDATE: capture snapshot assembly (`history/ops.rs:273–310`, `319–339`) — extract final assembly only; tests at `history/ops.rs:588–617,677–699`.
- RETAINED: image vs thumbnail loading (distinct blob table/fallback), UUID-shaped newtypes (identity boundaries), compat wrappers (adapter role), whole-prepare merge (ordering-sensitive), config validation lookalikes (distinct diagnostics).

### Server (`chatbot-server/src`)
- CANDIDATE: chat/regenerate prepare-error mapping (`chat.rs:224–273`, `regenerate.rs:207–255`) — narrow shared mapper; route coverage in `tests/provider_config_isolation.rs:669–947`.
- CANDIDATE: memory mutation error mapping (`memory.rs:122–158`, `225–261`) — share mapping only; coverage in `tests/memory.rs`.
- CANDIDATE: OpenAI request setup (`providers/openai.rs:216–245`, `353–382`) — extract within adapter; retry tests at `:1152–1203`.
- RETAINED: whole stream handlers (distinct capture/index/lease duties), provider wire parsers (distinct event semantics), TTS/STT permit lifetimes (deliberately different), policy/compat wrappers, response builders (distinct contexts).

### Browser + GPU (`static/*`, `chatbot-cuda/*`)
- CANDIDATE: sync/async CSRF header builders (`static/session-client.js:359–375`) — shared sync builder preserving both return types.
- CANDIDATE: base64 salt decode loop (`static/credential-crypto.js:57–80`) — delegate preserving `atobImpl` validation/errors.
- CANDIDATE: Kokoro warmup loop (`chatbot-cuda/src/service.py:190–227`) — needs warmup-failure characterization first (`chatbot-cuda/tests/test_service.py:68–100` covers choice/failure only).
- RETAINED: sentence queues/cancellation walks (distinct ownership/order), decoder tag handling (MOD-010 protocol boundary), voice-text rule order (load-bearing), bridge/codec parallels (platform-specific), renderer adapters/templates/CSS (sink/scoping boundaries).

### Native + ops (`android/*`, `dns/*`, `deploy/*`, `.github/*`, `scripts/*`)
- CANDIDATE: DNS upstream filtering (`dns/forwarder.py:167–180`) — extract exact filter op; covered by `dns/tests/test_resolver.py:68–92`.
- CANDIDATE: DNS relay preflight (`dns/forwarder.py:270–276`, `309–317`) — shared preflight; covered by `dns/tests/test_forwarder.py:115–222`.
- RETAINED (needs coverage first): Android origin-selection fallbacks — `ServerUrlSettingStore.java:91–105` is the shared entry point but callers differ and lack Java unit coverage.
- RETAINED: settings/cookie-purge paths (distinct scopes), mic/playback/car similarities (distinct sources/framing/policies; car protocol deferred), deploy/CI/Docker repeats (intentional environment differences).

### Batch order
- ABS-001: DNS forwarder dedup (filtering + preflight) — one file, test-covered, smallest blast radius.
- ABS-002 (planned): server error-mapper sharing (prepare-error + mutation-error mappers).
- Later: media AAD, capture assembly, OpenAI setup, JS builders — each with prerequisite assertions where noted.

## Session 065 — ABS-002 implementation, 2026-09-28

Delegated to a worker with exclusive ownership of `chat.rs`, `regenerate.rs`, `memory.rs`, `chat_utils.rs`; primary reviewed the branch-by-branch parity and accepted.

- Extracted `map_prepare_error` into `chat_utils.rs`: computes the eligible saved-turn message per variant (Validation always, History via `saved_error_message()`, Session only for `AuthenticatedBootstrapMisuse`, Policy never), saves the nonempty-message turn when eligible, otherwise maps to the original per-variant HTTP error. Both handlers call it with their own chat/session/payload/key — preparation, completion, success, and guest paths untouched.
- Extracted `map_mutation_mirror_error` in `memory.rs`: the six-arm `MutationMirrorError` mapping moved verbatim into one helper shared by the memory and system-prompt updaters.
- Verification (all exit 0): `provider_config_isolation` 23/23 job `20260928T193315-cb11c7c82348`; `memory` job `20260928T193436-97743165f4e3`; `chat` job `20260928T193521-961207d1bcfe`; `regenerate` job `20260928T193536-2a0fa2b1a3ad`. Full workspace suite plus record here at batch close.

## Session 066 — ABS-003 implementation, 2026-09-28

Delegated to a worker with exclusive ownership of `history/api.rs`, `history/crypto.rs`, `history/ops.rs` (+ `session.rs` inspected, untouched); primary reviewed the diff and accepted.

- `crypto.rs`: `build_image_aad`/`build_thumb_aad` now delegate to private `build_media_aad(user, set, image, kind)` — byte-identical AAD, capacity unchanged.
- `ops.rs`: `apply_regenerate`/`apply_chat_append` share only final `snapshot_from_capture` assembly; index/capacity logic untouched.
- `api.rs`: both first-turn append paths share `auto_name_first_turn` (placeholder check, derivation, exclusions, existing-name lookup, dedup) with each path's CAS/commit ordering preserved; the two pre-existing spelling variants (dedup-if-exists vs if/else) were semantically identical. Two new naming-outcome assertions (direct + capture paths, dedup case) added first per refactoring rules.
- Skipped with rationale: `session.rs` memory/prompt mirror pairs — sharing durable-write/mirror paths needs broader control-flow changes around post-durable failures and mismatch handling; deferred rather than forced.
- Verification (all exit 0): baseline lib 182/182 job `20260928T193712-1f710e0ea76c`, snapshot 7/7, mirror 10/10; final lib 184/184 (2 new) job `20260928T194058-c06e901a38e8`, snapshot 7/7, mirror 10/10. Full workspace suite plus record here at batch close.

## Session 067 — ABS-004 implementation, 2026-09-28

Delegated to a worker with exclusive ownership of `providers/openai.rs`, `static/session-client.js`, `static/credential-crypto.js` (`chatbot-cuda/src/service.py` inspected, untouched); primary verified the equivalence and accepted.

- `openai.rs`: both stream paths share `request_setup(messages, tools)` — key selection, routing options, payload defaults, URL construction; `tools=None→(None,None)`, `Some→(Some(vec),Some("auto"))` exactly as before; tool fields/stream types stay distinct per path.
- `session-client.js`: `withCsrfAsync` delegates to the sync `withCsrf` (copy-on-write via `Object.assign`, token attach); async wrapping preserves the Promise return. `chat.js:315–321` already delegates to this owner — no cross-file clone remains.
- `credential-crypto.js`: `decodeSaltB64` delegates to `decodeBase64` — identical `atobImpl` validation, decode loop, and byte output; the named wrapper stays as the salt-specific API.
- Skipped with rationale: Kokoro warmup extraction needs a warmup-failure characterization test in a read-only test file — deferred rather than forced.
- Verification (all exit 0): openai lib filter 12/12 job `20260928T194830-5dd32cff52d5`, `provider_messages` 4/4, `provider_config_isolation` 23/23, `session_client` 10/10, `credential_crypto` 4/4, `js_syntax` 11/11, cuda `test_service.py` 16/16 direct. Full workspace suite plus closure record here at phase close.

## Session 068 — remaining-units sweep, 2026-09-28

Three parallel read-only workers covered every unit untouched by sessions 063–067; primary synthesized. Honest depth notes inline.

### Core remainder (full source reads incl. inline tests)
- CANDIDATE (implemented in ABS-005): `constant_time_eq` clones (`user_store.rs:530–539`, `remember_store.rs:474–483`, `session_identity.rs:343–352`) → centralized in `fernet_crypto.rs` with a new direct test; image-edit skeleton (`chat_images.rs:298–320`, `460–486`) → shared helper keeping both replacement rules.
- RETAINED: fail-closed config/external-target validation; logging adapter; zeroizing key type; persistence/legacy export boundaries; prompt budgeting + image-slot order; rate-limit queues; names rules; Fernet helper; store composition timing; agent record/CAS duties; egress gates. `legacy_sets_json/store.rs` setters look clone-like but lack direct setter coverage — no forced dedup. Cross-component: image-tag scanning also in `providers/message_utils.rs:11–43` with different trim/output — not a bounded fix.
- Deferred: secure-flag choice sharing (per-caller config-read timing differs).

### Server remainder (full reads of owned production files + test-support)
- CANDIDATE (implemented in ABS-006): page-response assembly (`home.rs:357–396`, `login.rs:634–667`, `signup.rs:133–164`) → `home::page_response_builder`; agent guard prefixes (`agent_connections.rs:182–188,198–204,223–229,237–243`, list path kept) → `mutation_context`; `request_context.rs:79–94` + `:99–115` → `resolve_with_fallback` preserving key-first order.
- RETAINED: STT vs TTS permit lifetimes; TTS token/codec/text/backend/store orderings; probes; log redaction; limiter identity; privacy coordinator; policy live-vs-owned timing; generation live projection order; constructor field combinations; store dispatch + CSRF ordering; cookie builder order; JSON-arm status/text/counter differences; startup/router composition; ticker-loop owners; provider constructors and search branches (distinct fallback rules); message parser; module decls; tool definition; fixture roles. Cross-component: STT/TTS bound-set auth and generation-vs-Brave dispatch noted, not merged.

### Browser/native/ops remainder (full reads: short JS units, templates, CI scripts, Helm values; skims: large JS/CSS/Android/deploy files at cited areas)
- CANDIDATE: `login.js:57–81` notice setter and `tts-playback.js:374–388` + `:547–567` retry decision — both need client characterization tests first; deferred, not implemented.
- RETAINED: renderer adapters, IndexedDB ops, crypto-boundary adapters, Trusted Types policies, VAD/codec constants, bridge fallbacks, fencing checks, lifecycle ownership, load-bearing voice-text order, event gate, message source, MOD-010 decoder boundary, capture gates, text/HTML sink split, slot policy, connection side effects, script order, forms, stylesheet layering; Android mic/TTS/credential-codec/audio-policy/stream/queue/route/session/service/hooks/notification/coordinator/receiver/keep-awake units; settings plugin/activity; resolver/validation/style/logger utilities; compose overrides, Helm chart, workflows, scripts (distinct triggers/permissions/resources).
- Cross-component dispositions (retain, characterize interop first): voice-text rules vs `tts/text.rs`; cookie transport Java vs `enc_key_cookies.rs`; 16-kHz assumptions JS vs `NativeMicPlugin.java:65`.

## Session 069 — ABS-005/006/007 implementation, 2026-09-28

Workers with exclusive file ownership implemented; primary reviewed every diff branch-by-branch and re-ran the CUDA gate.

- ABS-005: `chat_images.rs` shares `coalesce_edit_user_message_with` (both replacement rules kept; `None` arm preserved); `constant_time_eq` centralized in `fernet_crypto.rs` (byte-identical body, new direct test) with all three callers migrated. Verified: baseline lib 182→184 (naming tests), new helper test 1/1 pre-migration, final lib 185/185 job `20260928T202532-e16281f48f9c`, `account_store_inputs` 5/5.
- ABS-006: `request_context.rs` shares `resolve_with_fallback(history_image)` (key-before-session, fallback only for image); `agent_connections.rs` shares `mutation_context` (list path untouched); `home.rs` owns `page_response_builder` (headers, remember-cookie loop + warn, session-cookie match + injected warn) with login/signup delegating (`&[]` restored). Verified: context boundaries 14/14 + 18/18, agent 13/13, home 8/8, login 8/8, signup 2/2.
- ABS-007: `_warmup_kokoro` shared by both load branches (sentence/voice/break/warning identical; setup + VRAM logging stay put) behind a new warmup-failure characterization test (17/17 direct, primary re-run; `voice_service_lifecycle` 1 Rust / 64 Python green job `20260928T201806-f008437ab9e9`). Android origin delegation REVERTED: the migration compiled and was behavior-equivalent by source analysis, but the full suite proved it out of scope — existing guard `distribution::all_native_consumers_read_only_the_flavor_resource` mandates per-consumer `R.string.server_url` reads plus direct `resolveCanonical` calls (flavor-precedence architecture, MOD-017), and the new JUnit test is not executable in this gate. Per-consumer reads stay; the guard test is the source-backed rationale.

## Session 070 — full-read completion round, 2026-09-28

Two read-only workers closed every skim admitted in session 068; primary synthesized. Browser worker fully read `chat.js:1–4902` (setup/HTTP/rendering, playback/privacy/history/DOM, TTS/regenerate/edits, sets/requests/mic, voice/STT), `voice-lifecycle.js:1–469`, `tts-playback.js:1–981`, `voice-capture.js:1–427`, `chat-renderer.js:1–387`, `style.css:1–993`, `opencode-theme.css:1–703`, `login.js:1–447`. Verdicts: retain stream blocks (different residual-flush/console behavior), stop/finish orderings, capture/barge gates, text/HTML sinks, breakpoint precedence, cascade overrides — each with line evidence in the worker record. Android/deploy worker read every owned file 1→EOF: mic/TTS/coordinator/session/service/policy/route/stream/queue/decoder/hooks/notification/receiver/keep-awake, car service/session, logger, credential cookies/payload, settings activity/plugin, URL setting/resolver/style, file logger, all compose/Helm/workflow/script files. New bounded candidates with prerequisites: coordinator release (`VoiceModeSessionCoordinator.java:263–370`, needs ordering tests), complete-clip read (`NativeVoiceTtsPlugin.java:317–399`, needs chunking/truncation/cancellation cases), button-style setup (`ServerUiStyle.java:125–155`, needs view assertions). Nothing left partially read.

## Session 071 — ABS-008 implementation, 2026-09-28

Workers with exclusive ownership implemented; primary reviewed every diff and the new fixtures.

- Client: `login.js` warning/error setters share one DOM/fallback setter (exact class transitions preserved); `tts-playback.js` fixed-list and live queues share only `desktopSentenceRetryDelay` (identical guard, increment, backoff cap; timers/guards/lifecycle untouched). New `phase3_client_characterization` Node target pins notice text/classes/missing-element logging plus both queues' retry schedules with/without voice mode — green before and after the edit.
- Android: `MainActivity`/`NativeSecureKeyPlugin` delegate to `ServerUrlSettingStore.selected/flavorDefault` (no caller-contract difference demonstrated); new `server_setting_store_selection_runs_on_shipped_java` fixture compiles the shipped store/setting/resolver against minimal framework doubles and runs both flavors, missing-resource, invalid/valid override, and null-context cases through the executor's javac. `distribution.rs` guard migrated with intent preserved: anti-Bridge, anti-literal, `setServerUrl` pin, VoiceScreen/ClientLogReporter checks intact; per-file spelling requirements moved to the shared store (resource read + canonical resolution + override selection asserted there).
- Verification: characterization 1/1 pre + post (`20260928T220838`, `20260928T221355`), `js_syntax` 11/11, `tts_sentence_boundaries` 5/5, `distribution` 12/12 (`20260928T221428`, `20260928T222647`), APK `BUILD SUCCESSFUL` 72 tasks (`20260928T221140`). Two source-spelling assertions broken by the behavior-preserving extractions were migrated with intent preserved (user-authorized): `voice_mode_reliability` bound/voice-mode pins now check the shared-helper call plus the bound in the helper (`voice_mode_reliability` 51/51 job `20260928T223504`); `server_settings_entry` origin pin now checks the shared-store delegation (`server_settings_entry` 4/4 job `20260928T223553`). An intermediate full run caught both before migration (exit 101, jobs `20260928T221748`, `20260928T222659`) — the gate worked as designed.

## Session 072 — remaining-sections review and ABS-009–012, 2026-09-28

Five read-only workers reviewed every section the ledger still showed as untouched, with per-section line ranges; four implementing workers (disjoint files) executed the covered candidates. Primary reviewed every diff.

- C02 (`session.rs:1–3555` full read): shared `load_prepare_snapshot_with_prompt` (both builders keep their mirror assignments) and `apply_history_clear_mutation` (delete/reset keep distinct durable ops; memory/prompt/page-load excluded on resolution semantics). Verified: lib 185/185, mirror 10/10, isolation 8/8, regenerate 1/1. C02 A advances to R.
- C04 (all `history/` modules): `mutate_content` for the four content mutations (rename/capture paths excluded on lock/reload semantics); `check_append`/`push_pair` shared by both append paths; `images_for_entries` taking only caller-selected entries (missing-image behavior preserved). Verified: lib 185/185, snapshot 7/7, mirror 10/10. C04 A advances to R.
- S01/S04: `forward_provider_stream` shared loop (regenerate keeps its `(regenerate)` error log via flag; both keep owned finalizers); `saved_provider_error_response` shared construction (chat persists via append with `None` index, regenerate via replace at its captured index); xAI `with_fake_key` preserving live-env vs explicit-key timing. Verified: lease 8/8, dispatch 15/15, finalize 5/5, error-ownership 4/4, isolation 23/23. S03 (sets/preferences/reset fully read, retains recorded) advances to R; S01/S04 stay P with the extended scope below.
- W05: `conversation-state.js` shares the binding predicate (sequence check + public APIs intact); `credential-metadata.js` listing reuses the slot-key helpers (value check + defaults intact). Existing harnesses covered both (binding 1/1, state 11/11, metadata 6/6, `js_syntax` 11/11) — no new tests needed. W05 A advances to R.
- N01 (all files fully read): retains recorded with cross-file dispositions (credential-clearing preserves session vs switch purges it; biometric resume vs credential unlock; log caps on opposite sides of the trust boundary). N01 A advances to R.

## Session 064 — ABS-001 implementation, 2026-09-28

Delegated to a worker with exclusive ownership of `dns/forwarder.py`; primary reviewed the diff and re-ran the gate.

- Extracted `_usable_nameservers(host_etc, host_run, host_abs)` — the exact non-loopback filter plus `[:MAX_UPSTREAMS]` cap, applied at the direct site and each stub fallback with identical order/behavior.
- Extracted `_query_txid(query, upstreams)` — the exact short-query/no-upstream guard plus TXID capture, shared by `forward_udp` and `forward_tcp`; transports and ordered failover untouched.
- Verification: `python3 -m unittest discover -s dns/tests -t dns` 31/31 OK (worker run plus primary re-run, per `dns/README.md` gate). Final full suite `temp/test-logs/abs001-full-20260928.log`: job `20260928T191728-ae8166f569a2`, exit 0, untruncated, 121 suites ok / 992 passed / 0 failed, including provider configuration checks.
