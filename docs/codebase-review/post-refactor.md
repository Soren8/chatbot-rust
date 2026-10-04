# Post-refactor codebase review

Initial review dated 2026-10-03 on `refactor@6c86a98`, after the seven authorized phases. One reviewer performed the source review, caller/test tracing and runtime probes; no subagents were used. The findings and evidence through the original Verification section preserve that review's source snapshot. Current remediation and later verification are recorded separately in the 2026-10-04 section below.

## Verdict

The ownership refactor established useful boundaries, but completion of the seven passes was not an issue-free release gate. The original review and subsequent user report track **22 follow-ups: seven P1, fourteen P2 and one P3**. Nine behavior findings were reproduced against the freshly built disposable app or its shipped browser module; the actual CI secret scanner also failed. PR-022 adds the user's inference crash/unload report with source confirmation of the missing outbound bounds. The dated update below records the subsequent implementations and verification levels without rewriting those original observations.

P1 means a security boundary, primary workflow or CI gate needs prompt attention. P2 means a concrete correctness/robustness follow-up. P3 means the review/architecture records need reconciliation. At the original 2026-10-03 snapshot, all findings were open and the recommendations below were proposed remediation. They are historical source findings, not current implementation status. Existing accepted/deferred issues are listed separately.

## Confirmed remediation contracts

The user confirmed biometric/PIN unlock on Android cold entry with cached credentials, preserving the existing one-minute resume grace and confirmed continuing-background-voice exemption. The user also confirmed inline system-prompt saving when Send is accepted; stale/rejected admissions must make no prompt changes.

The user selected removal of SVG support and a 1024×1024 outbound image limit, preserving aspect ratio without upscaling. Raster originals retain their stored bytes and quality. Passive serving and restricted decoding belong to PR-001; the shared model-bound resizing policy belongs to PR-022.

## Coverage and method

The tracked inventory and [coverage units](coverage.md) guided a repository-wide production and integration review:

| Area | Reviewed boundaries |
| --- | --- |
| Rust composition/configuration | Startup, router/middleware order, background owners, `AppServices`, live/owned policy and generation adapters, config validation, error rendering and rate limiting. |
| Accounts and HTTP identity | Signup/password derivation, verifier enrollment/checking, first-open and writer locking, HTTP expiry, remember rotation/forget, account-key-cookie attribution and home restoration. |
| Chat/history | Prepare/lease/finalize, capture CAS, guest/authenticated mirrors, cache authentication/TTL/zeroization, logical/materialized image handling, page/pair reads, lifecycle/name/default operations, legacy migration, crypto framing and receipts. |
| Providers/agents | OpenAI and xAI stream success/failure/retry/search paths, Brave errors, message packing, connection CRUD/receipts/checks, destination validation, DNS pins and check deadlines. |
| Browser | All first-party JS units and `chat.js` composition; guest/authenticated startup, set binding, admission/replay/Stop, mutation recovery, rendering/attachments, credentials, capture, playback and sentence queues. Templates and custom styles were checked with their callers and rendered preview. |
| Android | Activity/resume/cold-start boundaries, keystore/cookie lifecycle and origin switching, microphone/route/foreground ownership, native TTS downloads/decoding/settlement, telemetry, Auto protocol and packaging integration. |
| Voice service/DNS | Settings, startup/device mapping, conversion/staging/inference lifetime, cancellation/shutdown, stream backpressure, DNS resolver refresh and UDP/TCP relay. |
| Build/operations/docs/tests | Cargo/Docker/Compose/Helm/Android build wiring, CI and secret scanning, dependency/asset distribution boundaries, completed-phase records and the test bodies/fixtures relevant to candidate findings. |

Tests were traced for the identified behavior gaps; this is not a claim that every assertion was re-audited or a line/branch coverage measurement. Vendored/minified/generated code, binary assets and development-environment wiring were reviewed at their integration/provenance boundaries. Protected `.env`, `.config.yml` and runtime `data/` were not read. The executor preview used its own dummy configuration and disposable data, not live application storage.

## Findings overview

| ID | Priority | Finding | Evidence |
| --- | --- | --- | --- |
| PR-001 | P1 | Stored SVG attachments can execute same-origin script outside the HTML page's CSP. | Runtime reproduced |
| PR-002 | P1 | Guest UI startup dereferences absent saved-set privacy and aborts initialization. | Runtime reproduced |
| PR-003 | P1 | Accepted `guest_…` usernames are treated as guest chat storage identities. | Runtime reproduced; mirror consequence traced |
| PR-004 | P1 | Native cold start can reuse persisted credentials without the cached-login unlock gate. | Source path; physical-device confirmation pending |
| PR-005 | P2 | New-set recovery sends `name`, while the server accepts `set_name`; retries create additional sets. | Runtime reproduced |
| PR-006 | P2 | Durable admission mutates the prompt before checking the caller's expected version. | Runtime reproduced |
| PR-007 | P2 | Reset and other remaining mutation callbacks lack conversation fencing. | Reset runtime reproduced; adjacent callbacks traced |
| PR-008 | P2 | Stop during pending admission neither cancels admission nor stops a subsequently admitted worker. | Shipped module reproduced with controlled transport |
| PR-009 | P2 | xAI in-band terminal failures are treated as successful stream completion. | Source; mock-provider regression missing |
| PR-010 | P1 | Brave failures retain the private query in URL-bearing errors logged by search. | Source; current privacy test bypasses HTTP |
| PR-011 | P2 | Cancellation during STT staging can orphan a plaintext WAV before inference takes ownership. | Source; staging-cancellation regression missing |
| PR-012 | P2 | Large decimal TTS text panics in number expansion. | Runtime reproduced |
| PR-013 | P2 | Maximum replay cursor overflows `cursor + 1`. | Debug preview panic reproduced; release wrapping traced |
| PR-014 | P2 | Concurrent default-set initialization can create duplicate undeletable defaults. | Source interleaving; deterministic concurrency test pending |
| PR-015 | P2 | First-open `users.json` initialization remains outside the writer lock and can truncate a concurrent write. | Source interleaving; current test's barrier excludes it |
| PR-016 | P2 | Controlled login/history-derived key buffers bypass zeroizing ownership. | Source; no heap-recovery claim |
| PR-017 | P3 | Architecture/backlog/coverage records still contradict completed changes. | Source and record comparison |
| PR-018 | P2 | Handheld native TTS consumes an expired token as a skipped clip rather than renewing its sentence. | Source; recovery claim and desktop behavior diverge |
| PR-019 | P1 | The CI secret-scan command fails on legitimate Connections DTO fields. | Actual command failed; 13 fixture checks passed |
| PR-020 | P2 | Configuration validates trimmed tiers/types but retains untrimmed runtime values. | Source; premium gate and dispatch consequences traced |
| PR-021 | P2 | Native API-26 calls are unguarded despite the declared API-24 minimum. | Source; API-24/25 device/emulator verification pending |
| PR-022 | P1 | Oversized model-bound images are forwarded without size bounds/resizing and can crash/unload inference. | User-reported backend failure; missing outbound bounds confirmed by source |

## Remediation status and verification — 2026-10-04

The findings and detailed source narratives below preserve what the 2026-10-03 review observed and recommended; where they say “not implemented,” that is historical wording. Current implementation dispositions and verification scope are summarized here. Focused verification and the consolidated release gate passed. This does not mean every finding is closed: PR-006 retains the explicit legacy-path boundary below, and platform/GPU/heap limits remain unverified.

| ID | Current implementation and evidence level | Remaining boundary |
| --- | --- | --- |
| PR-001 | New SVG submissions are rejected. Stored-image responses use recognized raster MIME only, `nosniff`, and `default-src 'none'; sandbox`; old active SVG bytes are not served as active documents. `image_safety` covers the response/upload boundary. | The original browser exploit remains the historical pre-fix observation; no claim is made about unrelated historical clients or stores. |
| PR-002 | Guest startup no longer assumes a saved-set privacy object exists; browser/state regressions are included in the focused integration checks. | No new live deployment or user-runtime observation is claimed. |
| PR-003 | Chat-session encryption classification now uses authenticated identity rather than the `guest_` name prefix, preserving prefixed account usernames. Covered by core and server-owned-generation focused suites. | No additional limitation recorded for this correction. |
| PR-004 | Cold native process entry gates on cached credential cookies or sealed credential slots and hides the WebView before authenticated content can render. The JVM gate fixtures and physical-debug APK build cover off-device behavior/build integration. | Physical-device cold launch, surviving live-cookie jar, rotation and process-death flows remain unverified on hardware. |
| PR-005 | Explicit create and recovery use the server's `set_name` DTO consistently; browser recovery/distribution fixtures are included in the focused checks. | No live deployment/recovery session is claimed. |
| PR-006 | Durable admission checks the caller's set version before prompt mutation; accepted inline prompts commit via CAS and the resulting version is the capture baseline. Current/stale version, invalid regenerate index, model/type/privacy paths and the deterministic no-Brave legacy 403 preflight have focused coverage. | **Open source boundary:** a header-free request remains eligible for legacy Brave transport/setup. If that transport/setup fails after an inline prompt write, it can enter the legacy fallback/saved-error path after the prompt has changed. The durable admission guarantee does not close this compatibility path; do not mark PR-006 wholly fixed. |
| PR-007 | Mutation callbacks retain and fence the initiating set/generation through response and retry handling; focused browser state/application checks are green. | No claim that every possible live multi-tab interleaving has been exercised. |
| PR-008 | Stop intent is retained across a pending durable admission and applied if that admission is later accepted; focused activity-sync checks are green. | The logged checks use controlled transports; no live server deployment is claimed. |
| PR-009 | xAI unsuccessful terminal outcomes are handled as provider failures instead of normal stream completion; provider/dispatch regressions are included in focused checks. | No real upstream-provider run is claimed. |
| PR-010 | Brave transport/status/parse errors no longer retain query-bearing URL material in the surfaced/logged error path. Mock HTTP regressions verify sanitized errors, captured logs, and the actual model follow-up request. | External provider/proxy logging remains outside these checks. |
| PR-011 | STT staging and inference now have cleanup ownership across cancellation/failure handoff; the voice-service Python focused suite is green. | No GPU inference was run for this lifetime fix. |
| PR-012 | Large decimal components use a bounded safe pronunciation path rather than panicking before admission; focused server tests are green. | No additional limitation recorded for this correction. |
| PR-013 | Replay-cursor arithmetic handles maximum values without wraparound; generation-focused checks are green. | No additional limitation recorded for this correction. |
| PR-014 | Default-set creation is serialized under its owner so concurrent first initialization returns one default; the deterministic core regression is included in the focused core suite. | No multi-process/shared-database guarantee is implied. |
| PR-015 | First-open `users.json` initialization uses non-replacing atomic publication; the delayed-opener regression is included in the focused core suite. | This is distinct from TQ-004's process-local ordinary read/modify/write lock; cross-process read/modify/write serialization is not promised. |
| PR-016 | Password-login, server-derived and history-key intermediates now use zeroizing ownership where controlled by the application. | No heap-recovery, framework/transport/library-copy, or complete process-memory wipe claim is made. |
| PR-017 | Current service/error/lease/voice-streaming descriptions and the owned review ledgers were reconciled; T/D marks describe Phase 6/7 scope rather than assertion- or line-level completeness. | Historical Phase 6/7 dispositions and accepted/deferred work remain as recorded; this reconciliation does not close other passes' open items. |
| PR-018 | Native clips report explicit `played`, `expired`, or `failed` outcomes. One expiry re-admits using the original sentence operation and replays pending lookahead in order; failures/repeated expiry stop and surface rather than silently consuming the sentence. Native queue and playback fixtures are included in focused checks. | Physical-device download, token expiry and audio playback remain unverified. |
| PR-019 | The actual served-asset scanner output is clean; the final synthetic fixture log records 18 passing cases and 0 failures. | This is the scanner's defined secret-pattern boundary, not a general secret audit of external systems. |
| PR-020 | Validated provider type/tier values are normalized for runtime use; the configuration regression is included in the core focused suite. | Protected operator configuration was not read or validated here. |
| PR-021 | Audio-focus calls use an API-compatible adapter, and the physical-debug APK compiles. JVM distribution fixtures cover the adapter boundary. | API-24/25 device/emulator execution remains unverified; APK compilation does not establish old-OS behavior. |
| PR-022 | Every model-bound user-image part is normalized to at most 1024×1024, aspect-preserving, without upscaling; malformed, non-raster and over-budget images are omitted. Only outbound renditions change; stored raster-original bytes/quality remain unchanged. Valid PNG image fixtures retain their assertions. | The crash/model unload is the user's report, not an agent reproduction. No GPU was loaded and no deliberate OOM was attempted. User acceptance was: “looks like the image change works”; this is user feedback, not a claim that the agent deployed the change. |

### Verification record

Focused checks recorded in `temp/test-logs/pr-integration-*` include: 208 core unit tests; 9 model-image-bound tests; 4 server image-safety tests; 25 distribution fixtures; 72 Python voice-service tests; 12 server-owned-generation tests; 15 generation-dispatch tests; 4 provider-message tests; 3 native TTS queue tests; 14 history-read-cost tests; 10 playback-retarget tests; and 106 broader server unit tests. These are individual targeted results, not one summed count or the consolidated release gate.

The final actual served-asset scan reports no secret tokens (`temp/test-logs/pr-scanner-actual-final.log`, exit 0); the final synthetic scanner fixture log records 18/18 passing cases (`temp/test-logs/pr-scanner-fixtures-final.log`). The image fixture now uses valid PNG data while retaining its assertions; native playback fixtures supply explicit `played` outcomes. Existing behavior contracts were not weakened. The Android physical-debug APK artifact job `20261004T014542-5ff2b53112af` completed with `exit=0`; production Java sources have not changed since that build. This verifies compilation/artifact creation only, not installation or device behavior.

The consolidated final integrated gate passed: `temp/test-logs/pr-final-integrated.log`, job `20261004T061453-813f3ffc3d50`, `exit=0`, `log_truncated=False`. It reports **153 nonzero Rust test-result blocks, 1,199 passed, 0 failed**; zero-test result blocks are excluded. Nested Python suites are separate: DNS 34 passed and voice-service 72 passed; they are not added to the Rust counts. Earlier broad attempts recorded failures in `pr-integration-completion-gate-final.log` and `pr-final-full-complete.log`; those historical attempts are superseded for gate status by this final exit-0 run. The remaining PR-006 legacy boundary and device/GPU/heap limitations above remain open despite the green gate.

## Detailed findings

### PR-001 — Active attachment content escapes page CSP

`chatbot-core/src/chat_images.rs:594–615, 674–686` accepts base64 bytes with an `image/*` MIME and stores the original when thumbnail decoding fails. `chatbot-server/src/sets.rs:644–694, 944–951` serves that MIME/body as an inline document without a content CSP. The CSP in `home.rs:384–399` protects HTML page responses, not this resource.

A synthetic SVG was saved through the existing saved-error-turn path, then opened at `/history_image/{set_id}/{version}/0/0`. Chromium received `200 image/svg+xml`, no CSP, and executed its script. An `<img>` SVG preview is not the execution context demonstrated here: direct document navigation is. Imported untrusted SVGs therefore become script-capable documents on the authenticated application origin; HttpOnly cookies still accompany same-origin requests. This does not demonstrate unauthorized cross-user attachment insertion.

Remediation should constrain uploaded image formats/bytes or isolate active attachment documents with an appropriate response policy. Add a real-browser attachment-document regression in addition to MIME/thumbnail tests.

### PR-002 — Guest startup crashes before Send is registered

`static/chat.js:1233–1246` leaves `loadedPrivacy = null` and considers guests policy-ready. `refreshPrivacyControls` then evaluates `ready ? loadedPrivacy.level : ''` at `:1284`, even when `#privacy-select` is absent. `updateSearchToggleVisibility()` invokes that function at the start of the main ready callback (`:2786–2800`).

On a fresh guest page, Chromium raised `Cannot read properties of null (reading 'level')`; `window.sendMessage` remained `undefined`. The ready callback did not reach the Send/mic/voice bindings. Guest policy must not dereference a saved-set policy. Add full guest-page initialization coverage; existing route tests and isolated privacy-selector fixtures do not run this startup path.

### PR-003 — Guest and account identity namespaces overlap

`chatbot-core/src/names.rs:9–10, 28–36` accepts usernames beginning `guest_`. `session_identity.rs:362–366` uses the username verbatim as the authenticated chat session ID. `session.rs:358–364` decides `requires_cipher` from that ID prefix rather than authenticated identity.

A newly registered and password-authenticated `guest_review_…` account returned `400 authenticated session must load via history store` on durable chat. After the normal `/load_set` path, it returned `500 missing set privacy capture`. Its entry is guest-classified, so authenticated memory/prompt mirror data can also bypass `seal_session_data` (`session.rs:1925–1941, 2665–2668`).

Separate guest and user chat identities/ownership explicitly, including compatibility for existing prefixed accounts. Rejecting future names alone would leave those existing accounts broken. Cover signup/login/load/chat/regenerate with a prefixed username and verify mirror sealing.

### PR-004 — Native cold-start unlock boundary is incomplete

`android/app/src/main/java/com/chatbot/app/MainActivity.java:44–48, 125–174, 199–213` initializes `backgroundedAt` to zero and enforces resume unlock only after an elapsed background interval in that Activity instance. It creates the Bridge against the selected server without a cold-start credential gate.

`NativeSecureKeyPlugin.java:196–240` seals cookies but does not remove them; `purgeCachedCookies` is invoked from `static/login.js:262–265`, not native startup or authenticated chat. Remembered password login issues persistent remember/key cookies (`chatbot-server/src/login.rs:180–258`), and `/` restores/promotes them (`home.rs:50–154`). Opening directly into `/` with that jar can avoid `loginCachedAccount` and its biometric prompt. Activity recreation also loses the instance-local resume timestamp.

This is a concrete source-level alternate path around the documented native cached-login/at-rest-cookie boundary, not an on-device reproduction. Verify force-stop/process death, cold relaunch, rotation/recreation and server restart on a physical device. Native startup and credential-jar ownership must enforce the chosen unlock contract before authenticated content is exposed; the ordinary background-voice exemption should remain explicit.

### PR-005 — Create recovery does not use the server's explicit-name contract

`static/activity-sync.js:91–95` inserts `body.name`. The New button sends `{}` (`chat.js:3460–3478`). `chatbot-server/src/sets.rs:23–41, 220–241` reads only `set_name`, ignores the unknown `name`, and auto-names the request. This route does not consume the supplied idempotency receipt.

The preview let the first create succeed but replaced its acknowledgement with 503. Recovery resent the identical `{"name":"New Chat"}` body and created both `New Chat` and `New Chat 2`. `fixtures/activity_sync_test.js:126–129` asserts the incorrect `payload.name` against a mock, so it cannot catch the wire mismatch.

Use the actual explicit-name DTO and verify response-loss recovery across the browser/server boundary. Explicit-name collisions must resolve the already-created target rather than being presented as a new success or an unexplained error.

### PR-006 — Rejected durable requests can overwrite the prompt

`chatbot-core/src/session.rs:909–934` writes a differing supplied system prompt using the freshly read durable version and advances the snapshot version during prepare. Both generation handlers call prepare before `GenerationFeedback::capture` checks the request's `expected_version` (`chat.rs:328–363`, `regenerate.rs:200–235`, `generations.rs:56–65`). Tier/destination-policy rejection and provider setup failures can also occur after this write.

The preview sent expected version 0 against a version-1 set with a different prompt. Admission returned 409/current version 2, but `/load_set` showed that new prompt persisted at version 2. The caller's failed CAS did not prevent mutation. A current-version request with a differing prompt can likewise cause its own rejection by advancing the version before comparison.

Admission version/policy checks must precede side effects and retain an atomic/capture-consistent prompt contract. Cover stale and current durable requests with differing prompts, both handlers, and rejected provider/privacy/tier cases. Legacy inline-prompt behavior needs its own explicit compatibility decision.

### PR-007 — Remaining mutation replies can corrupt a replacement view

`static/chat.js:629–648` rebuilds Reset retries from the live selection, adopts response set IDs globally, and clears the live chat DOM on success without a captured set-generation check. Delete-message (`:2631–2677`), fork (`:2715–2736`) and rename/delete-set callbacks (`:3495–3555`) also lack the fencing applied to chat, memory and prompt saves.

The preview held Reset A's 409 reply, switched to B, then delivered the reply. The retry combined `set_id=A` with `set_name="Review B"`; success left the selector and loaded policy on B, `currentSetId()` on A, and cleared B's DOM with “Chat history has been reset for set Review B.” The durable reset still targeted A; the demonstrated corruption is the replacement view and active identity, not a proved durable reset of B.

Capture target/version/generation for each mutation and gate response application/retries through that binding. Add delayed success/conflict-after-switch tests for the remaining mutation families, rather than assuming the memory-save fences cover them.

### PR-008 — Stop cannot settle a pending admission

`activity-sync.js:271–292` discards `init.signal` when calling `start(payload, ...)`. `start` issues a separate request with no signal (`:223–227`), and `stop()` does nothing until `view` exists (`:245–247`). On late admission, the aborted original signal only detaches the adapter after attach. `chat.js:1860–1866` invokes this sequence for the Stop button.

A controlled transport running the shipped module held `/chat`, aborted the initiating controller and called Stop, then delivered 202. The admission transport remained un-aborted and no `/generations/{id}/stop` request was sent. A subsequent server-owned worker can continue despite the user's explicit Stop.

Track pending admission Stop intent through acknowledgement and issue Stop for any accepted generation, including response-loss replay. Merely aborting transport is insufficient when admission might already have succeeded. Cover both delayed first acknowledgement and accepted-but-lost acknowledgement.

### PR-009 — xAI terminal errors do not mark provider failure

`chatbot-server/src/providers/xai.rs:243–309` recognizes deltas, completion and search events; `response.failed`, `response.incomplete` and error events fall through. The successful-HTTP stream loop at `:182–199` also ends normally at EOF without validating a successful terminal event or consuming the residual line.

Consequently an HTTP-200 failed response can reach `forward_provider_stream` as normal completion (`chat.rs:104–141`), persist an empty/partial assistant turn, and report completion/saved rather than provider failure. Existing xAI privacy tests exercise successful deltas and HTTP errors; SEC-012's in-band-error regression exercises only OpenAI.

Add mock xAI failed/incomplete/error/EOF cases and map unsuccessful terminal outcomes to sanitized provider errors. Preserve the no-persist-on-provider-failure contract and never echo the upstream error payload into logs or streams.

### PR-010 — Brave's error URL leaks the query

`brave.rs:79–91` appends `q` to the URL and preserves reqwest send/status/JSON errors in the anyhow chain. `search.rs:107–109` logs that chain with `?e`. Reqwest URL-bearing errors contain the query; removing explicit query log fields did not sanitize this indirect path. Failure text is also injected into the follow-up prompt.

`provider_log_privacy.rs:133–151` supplies `CHATBOT_TEST_BRAVE_RESULTS`, so the “query never enters logs” test bypasses every HTTP failure above. Source confirms the missing URL redaction; this review did not send a private query to Brave or dynamically exercise its production endpoint.

Remove sensitive URL/query material at error construction and log bounded status/failure categories. Extend the injectable-endpoint tests to capture tracing on transport, non-2xx and malformed-JSON failures with a query sentinel.

### PR-011 — STT staging is outside cancellation-safe file ownership

`chatbot-cuda/src/main.py:145–148, 171–174` awaits `_stage_wav` through `asyncio.to_thread`, then passes its returned pathname to `transcribe_async`. Cancellation while that await is pending does not stop the staging thread: it can finish writing a `delete=False` plaintext WAV after the request loses its result. The inference job's `cleanup_path` owner (`service.py:410–468, 618–625`) has not yet received the path.

Current lifetime tests cover cancellation once the transcription worker owns the file, and `test_main.py:296–325` covers successful staging/cleanup. Neither closes this earlier handoff. A staging write failure can similarly leave the just-created file.

Establish cleanup ownership from file creation through staging and inference, including an abandoned staging result. Characterize cancellation with a barrier inside staging and inject a write failure; GPU inference is unnecessary for those tests.

### PR-012 — Large decimal text panics before TTS admission

`tts/text.rs:134–155` supports only 0–999, but `integer_to_words` calls it on `n / 1_000_000_000_000` without a bound (`:160–174`). Decimal expansion accepts a `u64` integer part (`:200–205, 446–449`).

Posting `{"text":"1000000000000000.0"}` to `/tts` in the preview produced a socket hangup and `index out of bounds: the len is 10 but the index is 10` at `tts/text.rs:149`. The server remained alive; this was a request-task panic. Ordinary speech containing sufficiently large decimal/version components can therefore break sentence admission and trigger recovery retries.

Handle larger groups or fall back to safe digit/text pronunciation. Test the 999/1000-trillion boundary and maximum `u64` components through sanitization and HTTP admission.

### PR-013 — Replay cursor arithmetic is not bounded

`generations.rs:573–586` accepts any `u64` `after`; `State::events_after` computes `(cursor + 1).saturating_sub(first)` at `:105`. Saturation applies after the overflowing addition.

An authenticated preview request to an owned generation with `after=18446744073709551615` panicked at `generations.rs:105` and aborted the transfer. In an ordinary release profile without overflow checks, the addition wraps and can replay buffered events from the beginning instead of returning no events. This is distinct from the accepted buffer-size/coalescing policy.

Use checked/bounded cursor arithmetic or reject invalid/future cursors under a defined protocol rule. Cover maximum cursors and cursors beyond the last event, including the release behavior.

### PR-014 — Default-set creation is not serialized with uniqueness

`history/api.rs:818–834` checks the set list, then calls `store.create_set` directly without `name_mutation_locks`. The store checks only whether the new UUID exists (`store/mod.rs:642–660`), not whether that user already has a default. Two first readers can both observe no default and insert distinct default UUIDs. Both sets then resist rename/delete.

The unsafe interleaving is source-confirmed, not reproduced in this review. Existing create-name locks and transactional legacy migration do not cover this separate default initializer. Add a deterministic concurrent initialization test, then arbitrate the default invariant under the relevant user/lifecycle owner. Check interactions with explicit create/default-name compatibility too.

### PR-015 — First-open account initialization can still overwrite data

`user_store.rs:147–150` uses `exists()` followed by truncating `File::create` and writes `{}` outside `users_file_lock`. One opener can observe absence, pause, and overwrite the file after another opener creates it and commits a signup. The TQ-004 locks on `create_user` and `update_user_preferences` do not include initialization.

`user_store_concurrency.rs:27–29` waits until every store has opened before permitting the first mutation, specifically excluding this interleaving. This is a narrower remaining initialization race, not evidence that the fixed ordinary read/modify/write case still fails. Use non-destructive, atomic initialization coordinated with writers and add a first-open/write regression.

### PR-016 — Key zeroization covers only some controlled owners

`EncryptionKey` zeroizes its own vector on drop. Password login instead transports the storage key as `Option<Vec<u8>>` and returns a plain `Vec<u8>` from the blocking task (`login.rs:120–149, 245–258`). Server derivation uses an ordinary derived array/base64 vector (`user_store.rs:246–249`). History AEAD uses ordinary HKDF output arrays (`history/crypto.rs:194–220, 227–233`), unlike the explicit wiping in connection and receipt crypto.

Those application-controlled key copies are freed normally, not wiped, despite the stronger request-key-zeroization wording. No standing-key API, heap recovery or post-free readability was demonstrated. Apply zeroizing ownership to controlled intermediate keys and make the documented guarantee precise about framework/transport/library copies; cached plaintext snapshots and key buffers are different obligations.

### PR-017 — Completion records still leave stale architectural claims

Examples requiring reconciliation:

- `findings.md` retains COR-001 as an unresolved ordinary user-store update race although TQ-004 records its process-local fix; the narrower initialization case is PR-015.
- `design.md:39, 43, 45, 73, 79, 85` retains claims of incomplete injection, ambient production account/chat ownership and a removed `ServiceResponse` carrier alongside later descriptions of the completed owners.
- `design.md:47` and the MOD-006 ledger still describe leased expiry/recreation settlement as open, while current leases retain the acquired entry and locked entries survive purge; `generation_lease_ownership.rs` directly covers that case. Compatibility/pre-prepare semantics should be identified separately.
- `design.md:65` describes an unbounded, uncancelled/unjoined streaming bridge, while `service.py` owns a four-item queue, cooperative cancellation and bounded shutdown join.
- The per-unit coverage table still leaves every T/D cell empty despite whole-repository Phase 6/7 completion prose, and `boundaries.md` retains obsolete credential/global-owner descriptions and a duplicated “Open boundary” heading.
- `deploy/helm/chatbot/values.yaml:7` still says root Compose uses a bridge, although its webserver uses host networking.

Reconcile the living architecture and ledger dispositions against code/evidence, distinguishing completed production fixes, compatibility surfaces, accepted decisions and genuinely open work. Completed phases should not require readers to reconstruct chronology from contradictory current-tense paragraphs.

### PR-018 — Native expired-token recovery stops at the plugin boundary

`NativeVoiceTtsPlugin.java:290–295` returns `null` for a 404 token. Its worker then emits `clipConsumed` (`:200–217`), and `tts-playback.js:778–784` releases the sentence slot. The handheld job retains no renewal handoff or sentence operation ID for a new token; failed native downloads are also consumed without a JS failure outcome. Desktop download recovery does renew a 404 under the original sentence key (`tts-playback.js:138–150`). Auto has a separate renewal helper.

This contradicts the handheld expired-token-renewal claim in `design.md:103` and leaves a sentence silently skipped after token expiry/eviction. No physical download/playback reproduction was performed. Settle the handheld renewal/failure outcome under the shared sentence owner and test a 404 through the real plugin-to-JS boundary; a mock bridge accepting an enqueue does not establish renewal.

### PR-019 — Cargo green does not imply the separate secret-scan job is green

`.github/workflows/ci.yml:17–23` runs `.github/scripts/verify_no_secrets.sh`. That script rejects every `base_url` occurrence in served assets. The actual repository invocation exited 1 on four lines of `static/agent-connections.js` (27, 72, 101, 160), all legitimate error/record/DTO field names for the user-owned connection UI. This probe found no embedded credential value.

The scanner's 13 synthetic fixtures passed, including cases deliberately rejecting `base_url`. The new allowed Connections surface and the old scanner contract were never reconciled; the Cargo suite does not execute this CI step.

Distinguish intentional user-owned connection metadata from operator provider configuration/secret leakage, retaining positive and negative scanner regressions. Include the real served-asset scan in the relevant release validation; deleting the UI or globally ignoring the file is not a justified resolution.

### PR-020 — Config normalization and enforcement disagree

`config.rs:758–779` validates `type` and `tier` after trim/lowercase, but `ProviderConfig::finalize` does not retain that normalization. The premium gate in `session.rs:805–812` lowercases without trimming, and provider listing in `generation_deps.rs:305–310` compares without trimming. A validated `tier: " premium "` therefore avoids both premium filtering and server premium enforcement. `type: " openai "` similarly validates but is rejected by runtime dispatch.

This is source-confirmed for whitespace-bearing configuration, not observed on the operator's protected config. Normalize the stored values or reject noncanonical spellings consistently. Add config-to-admission tests for accepted whitespace/case variants, not only validator tests.

### PR-021 — Native runtime calls exceed the declared minimum SDK

`android/variables.gradle:2` declares `minSdkVersion = 24`. Native microphone focus (`NativeMicPlugin.java:335–360`) and standalone/voice TTS focus (`NativeVoiceTtsPlugin.java:572–603`) construct `AudioFocusRequest` without an API-26 guard. The plugin's TTS abandonment guard does not protect that construction path. Origin-scoped credential slots also use `java.util.Base64` (`util/ServerUrlSetting.java:189–205`), introduced on Android API 26, with no core-library-desugaring setup in the inspected app Gradle wiring.

The focus calls alone leave advertised API-24/25 voice/playback paths exposed to unavailable platform classes; origin slot handling adds another compatibility boundary. This review did not run those Android versions. Honor the declared minimum with version-gated native APIs and verify API-24/25 app entry, password/cached login, voice mode and standalone playback. Current JVM stubs and a modern-SDK APK compile cannot establish old-OS compatibility.

### PR-022 — Bound and resize every model-bound image

User report (verbatim):

> currently we naively forward uploaded images to the language model, if they're too large, it can crash the inference and cause the model to become unloaded. so we need to set an image size bounds and auto-resize if necessary before passing to the LLM.

`chatbot-core/src/chat.rs:206–223, 258–259` reserves image slots and thumbnails older history, but appends the newest user turn unchanged at full fidelity. `chat_images.rs:219–238` also passes a chosen full-resolution history image through unchanged or resolves the original. `history/api.rs:837–854` returns stored original bytes for full fidelity and the thumbnail fallback. Regenerate prepares its coalesced full-image user message through the same path (`chatbot-server/src/regenerate.rs:275–305`). Provider mapping (`providers/message_utils.rs:25–35`) wraps those data URLs without validating dimensions, pixel count or encoded size. The HTTP request-byte cap and fixed vision-token estimates do not bound decoded image dimensions or inference memory.

Required remediation is a shared server-side outbound image policy before LLM dispatch: enforce explicit width/height, total-pixel and encoded-payload limits, preserve aspect ratio, and automatically downsize/re-encode oversized valid images. Apply it to every new-turn attachment, selected historical image, thumbnail-to-original fallback and regenerated/edit image across both provider paths; the existing full-resolution-slot count is not a per-image size bound. Undersized images should not be upscaled. Unreadable/unsupported payloads must produce a controlled outcome rather than bypassing the bounds as raw data URLs, and image decoding itself needs resource limits.

Keep outbound renditions distinct from durable originals so model resizing does not silently reduce stored-photo quality, subject to PR-001's safe-format/original-serving contract. Characterize large landscape/portrait and highly compressed high-pixel-count fixtures, already-small images, malformed inputs and multiple attachments. Capture actual outgoing provider payloads for chat, regenerate and retained history; verify dimensions/pixels/bytes and stored-original fidelity. Backend-specific defaults or overrides need agreed limits and provider-configuration validation if configuration is added.

The inference crash/model unload is user-reported, not reproduced in this review. The forwarding gap is source-confirmed; no GPU model was loaded and no deliberate OOM was attempted. The affected backend/model and safe image budget remain inputs for choosing concrete limits. This is an availability/resource-bound finding independent of SVG script execution.

## Existing work still requiring a disposition

These are not counted as new discoveries:

- **COR-003:** reads can combine independently acquired redb snapshots; cache/materialization/page/pair paths still need a coherent read contract and deterministic concurrent-write reproduction. Version-only image URLs are not snapshot reads.
- **SEC-001:** trusted ingress/proxy headers and direct HTTP/LAN/native cookie behavior remain an operator/topology decision. GET logout/CSRF, legacy PRF support and voice-backend/DNS authentication scope remain explicitly deferred.
- **MOD-013/017 and Auto:** host allowlisting and the supported car auth/protocol/transport contract remain open. Auto's selected-set lookup compares saved preferences to display names while the browser stores selector IDs, and its WAV fallback is written as raw PCM; these remain part of that deferred interoperability scope.
- **Voice settings/device selection:** `start.sh` exports the physical index as `CUDA_VISIBLE_DEVICES`; `settings.py` then uses that string as a logical CUDA index, although visible devices are renumbered. The multi-GPU case and Rust/Python configuration/enablement alignment remain under the known settings/distribution follow-up; no GPU models were loaded here.
- **Performance/product decisions:** proxy compression/NDJSON flushing, COEP middleware placement/product impact, GPU lookahead/timing, mic main-looper cost, inline Opus encoding and per-owner concurrency remain subject to their recorded measurements/decisions. This review adds no fabricated timing or memory benchmark.

The current production lease, owned-service composition, manifest-authenticated cache-hit, privacy permit/invalidation and typed error boundaries were retained in the review assessment. They are not proposals for another broad refactor.

## Additional focused characterization leads

These source observations need narrowly scoped reproductions before assigning a separate finding/disposition; they are not included in the twenty-two prioritized findings:

- **Guest settings before the first turn:** `session.rs:444–469` makes memory/prompt updates no-ops when no chat entry exists, while guest HTTP handlers return success. Guest prepare then initializes/clears those fields (`:877–904`). Cover save-before-first-chat independently of the PR-002 browser crash.
- **Wire/projection parity (MOD-010):** durable `EventText` (`generations.rs:407–445`) recognizes `<think>`/`<thinking>` closes, while the browser decoder and core thought stripping additionally support `[BEGIN FINAL RESPONSE]`. Cover that marker and split-marker/live/recovered/native projections; a successful `<think>…</think>` test does not establish parity.
- **Large upstream numeric hints:** `openai.rs:543–550` converts a finite `Retry-After` to `Duration` before applying the configured cap. Exercise an out-of-range finite value such as `1e100`, not only ordinary/capped/NaN headers.
- **Backend audio-rate validation:** Kokoro header parsing accepts a numeric zero (`tts/backend.rs:230–235`), while Opus resampling divides by the supplied rate (`tts_opus.rs:34–36`). Cover zero/extreme rates and malformed PCM with a bounded mock backend.
- **STT Ogg framing:** `native-audio.js:500–520` uses `ceil(packet.length / 255)` lacing segments. An exact multiple of 255 needs a zero-length terminating segment to mark a complete packet. Characterize packet lengths 254/255/256/510 through a real demuxer; default encoder output reaching this boundary was not established here.

## Verification evidence

All preview observations used a fresh build of the unchanged production code with the executor's secret-free deployment. No live service was rebuilt or restarted.

| Check | Result / evidence |
| --- | --- |
| Production-image build | `20261003T213622-728f55306542`, exit 0; snapshot SHA-256 `1b84d6d440efb2fe7922c0bee7f26d853e752d64b26b6752c053241f13ca0f05`. |
| Preview deployment | `20261003T213652-b59997c27429`; confirmed alias `preview-chatbot-rust`, internal network only, disposable data. |
| Guest/create/CAS/username probes | `temp/test-logs/post-refactor-review-ui-probe-verified.log`; observation assertions passed. Script: `temp/post-refactor-review-ui-probe.py`; guest capture: `temp/post-refactor-review-guest.png`. |
| Reset/SVG/number/cursor probes | `temp/test-logs/post-refactor-review-boundary-probe-complete.log`; observation assertions passed and `/health` remained 200. Script: `temp/post-refactor-review-boundary-probe.py`. |
| Pending-admission Stop | `temp/test-logs/post-refactor-review-admission-stop-probe.log`; shipped browser module with a controlled held acknowledgement, zero Stop calls and un-aborted admission transport. |
| Request-task panic logs | Status job `20261003T215642-c46fc7d70bd0`, saved in `temp/test-logs/post-refactor-review-preview-status.log`; identifies `tts/text.rs:149` and `generations.rs:105`. |
| Preview cleanup | `20261003T215642-66959105a447`, status stopped/exit 0. |
| Actual served-asset secret scan | **Failed, exit 1**; `temp/test-logs/post-refactor-review-secret-scan.log`. |
| Scanner fixture regression | Passed, 13 cases/0 failures; `temp/test-logs/post-refactor-review-secret-scan-fixtures.log`. |
| Inherited full Cargo gate | `20261003T210405-6ec64fba7bc9`: 1,171 Rust plus separate DNS 34 and voice 70 Python tests passed; provider-config example validation passed. That unchanged suite was not rerun, and does not cover the newly reproduced failures or the separate CI scanner. |

The exploratory probes assert the observed defects so the evidence scripts can finish successfully; they are not permanent regressions asserting correct product behavior and do not close any finding. Initial probe harness failures/timeouts were retained; the verified logs above contain the final successful observations. Source-only items need the focused red-first regressions described above when remediation is authorized. Physical Android/Auto, biometric hardware, real provider/GPU behavior and live ingress remain unvalidated by this review.

## Recommended ordering

Address the attachment execution boundary and model-bound image resizing, native credential entry paths, guest/account namespace failures, indirect query logging and failing CI contract first. Then repair create/admission/CAS/Stop and mutation fencing with end-to-end recovery tests. Follow with provider terminal outcomes, voice staging/native renewal, numeric bounds and initialization races. Reconcile the architecture/coverage records with those dispositions so the next completion gate states both what passed and what remains open.
