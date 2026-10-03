# Post-refactor codebase review

Reviewed 2026-10-03 on `refactor@6c86a98`, after the seven authorized phases. One reviewer performed the source review, caller/test tracing and runtime probes; no subagents were used. This record adds findings and verification evidence. Application code and permanent tests were not changed.

## Verdict

The ownership refactor has established useful boundaries, but completion of the seven passes is not an issue-free release gate. This review found **21 follow-ups: six P1, fourteen P2 and one P3**. Nine behavior findings were reproduced against the freshly built disposable app or its shipped browser module; the actual CI secret scanner also failed. The remaining findings distinguish source evidence from outstanding concurrency, provider or device reproduction.

P1 means a security boundary, primary workflow or CI gate needs prompt attention. P2 means a concrete correctness/robustness follow-up. P3 means the review/architecture records need reconciliation. All findings below are open; recommendations are proposed remediation, not implemented changes. Existing accepted/deferred issues are listed separately.

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

## Existing work still requiring a disposition

These are not counted as new discoveries:

- **COR-003:** reads can combine independently acquired redb snapshots; cache/materialization/page/pair paths still need a coherent read contract and deterministic concurrent-write reproduction. Version-only image URLs are not snapshot reads.
- **SEC-001:** trusted ingress/proxy headers and direct HTTP/LAN/native cookie behavior remain an operator/topology decision. GET logout/CSRF, legacy PRF support and voice-backend/DNS authentication scope remain explicitly deferred.
- **MOD-013/017 and Auto:** host allowlisting and the supported car auth/protocol/transport contract remain open. Auto's selected-set lookup compares saved preferences to display names while the browser stores selector IDs, and its WAV fallback is written as raw PCM; these remain part of that deferred interoperability scope.
- **Voice settings/device selection:** `start.sh` exports the physical index as `CUDA_VISIBLE_DEVICES`; `settings.py` then uses that string as a logical CUDA index, although visible devices are renumbered. The multi-GPU case and Rust/Python configuration/enablement alignment remain under the known settings/distribution follow-up; no GPU models were loaded here.
- **Performance/product decisions:** proxy compression/NDJSON flushing, COEP middleware placement/product impact, GPU lookahead/timing, mic main-looper cost, inline Opus encoding and per-owner concurrency remain subject to their recorded measurements/decisions. This review adds no fabricated timing or memory benchmark.

The current production lease, owned-service composition, manifest-authenticated cache-hit, privacy permit/invalidation and typed error boundaries were retained in the review assessment. They are not proposals for another broad refactor.

## Additional focused characterization leads

These source observations need narrowly scoped reproductions before assigning a separate finding/disposition; they are not included in the twenty-one prioritized findings:

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

Address the attachment execution boundary, native credential entry paths, guest/account namespace failures, indirect query logging and failing CI contract first. Then repair create/admission/CAS/Stop and mutation fencing with end-to-end recovery tests. Follow with provider terminal outcomes, voice staging/native renewal, numeric bounds and initialization races. Reconcile the architecture/coverage records with those dispositions so the next completion gate states both what passed and what remains open.
