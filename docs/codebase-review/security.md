# Security / privacy review (Phase 4)

Scope (user-authorized 2026-09-29): fresh repository-wide Sec inventory, behavior-tightening fixes allowed with red-first regressions, deferred items fixed if they fit this phase else deferred to owning pass, targeted `testctl` per batch plus final full suite + APK build.

## Session 075 — fresh Sec inventory, 2026-09-29

Four research-only workers inventoried exclusive partitions at `main@400631b` after reading `docs/design.md`, `docs/design-privacy.md`, `findings.md` (SEC-001, DOC-001) and `modularity.md` cross-pass table (SEC-002/003, COR-001/002, DOC-002/003, PERF-001, TEST-002-005, OPS-001). No edits in this session.

### Core (`chatbot-core/src`)
- CONFIRMED warm-cache key bypass: `history/api.rs:189–211,214–226` returns cached plaintext after user-ownership/version check only; `history/cache.rs:65–88` never authenticates the supplied key. Cold reads decrypt with the key. Conflicts with per-request verifier-before-decrypt (`design-privacy.md:67–72,90–94`). Sec fix: yes → SEC-004.
- Remember-family secret not authenticated: `remember_store.rs:114–156` rotates/peeks/revokes on family ownership without secret check vs `resume` at `:177–205` which hashes/compares. Fix only after caller-level red shows unauthorized rotation/revocation.
- Verifier/salt creation race: `user_store.rs:302–323,386–397` read-then-write without exclusion. Needs dynamic proof; red-first synchronized first-enrollment/salt test.
- COR-001 (`user_store.rs:187–209,419–445,494–526`), DOC-002 (`history/cache.rs:20–29,73–89,118–123,190–219` vs wipe-after-TTL promise), COR-003 (`history/store/chunks.rs:51–95,118–153`, `store/mod.rs:358–385`): confirmed by source, owning pass unless explicitly pulled into Sec.
- Privacy enforcement point is at dispatch/permit callers, not core prepare (`config.rs:96–111`, `config_source.rs:43–69`, `session.rs:911–947` verify key/tier only). Needs caller-level transmission regression before claiming leak.
- No new violation in HMAC-secret/per-request zeroization paths inspected (`user_store.rs:250–256`, `session.rs:731–755`, `enc_key.rs:5–9`, `account_service.rs:11–14`); transient derived-buffer erasure (`history/crypto.rs:188–233`) is hardening proposal only.

### Server (`chatbot-server/src`)
- SEC-001 proxy trust: `lib.rs:198–239` trusts client-supplied forwarding headers, `:241–269` strips `Secure` from all cookies; data key in those cookies (`enc_key_cookies.rs:118–128`). Needs ingress contract + dynamic proof; do not remove LAN compat on source alone.
- SEC-002 confirmed: `client_logs.rs:88–104` claims live-session gate but uses `rate_limit_identity`; `identity.rs:174–181` accepts unknown cookies. Fix → SEC-005.
- Client-log `source` unsanitized: `client_logs.rs:113–126` logs caller `source` verbatim; scrubber `:25–61` heuristic. Fix → SEC-005.
- xAI content logging confirmed: `providers/xai.rs:159–160,190–194` logs request body + raw chunks; error-body previews `providers/openai.rs:569–580`, `providers/xai.rs:205–210` may echo prompts/keys. Fix → SEC-006.
- Brave query logging confirmed: `search.rs:68–79` logs model query verbatim. Fix → SEC-006.
- TTS privacy-mode race confirmed: `tts.rs:158–179` checks mode under permit, drops permit before insert `:218–226`; `/set_privacy` invalidates under its own permit (`sets.rs:114–134`); delayed GET checks captured requirement (`tts.rs:282–355`, `tts/store.rs:38–64`). Fix: hold permit through insert → SEC-007.
- `GET /logout` without CSRF (`lib.rs:362`, `logout.rs:10–25`): defer contract decision; method change breaks switch-account flow.
- Login key buffer (`login.rs:126–139,231–249`): zeroizing-owner hardening proposal; characterize both key paths.

### Browser (`static/*`)
- Stale `storage_key` on retry: `static/login.js:86–93,360–398,405–441` removes hidden key only after successful derivation; fallback can submit prior attempt's key. Fix → SEC-008.
- Forget claims success pre-revocation: `static/login.js:302–321`, `static/chat.js:649–667` ignore `/login/forget` status. Fix → SEC-008.
- Standard offered as selectable: `static/templates/chat.html:110–123`, `static/chat.js:1128–1135,3066–3082` vs planned-not-selectable (`design-privacy.md:13–15,146–161`). Fix → SEC-008.
- Trusted Types identity policies (`static/tt.js:6–13`, CSP in `home.rs:17`) match documented trade-off (`design-privacy.md:140–144`); hardening needs sink review — defer.
- Legacy PRF unwrap (`static/enc-key.js:210–230,406–465`): defer pending legacy-support decision.
- Checked clean: set-name `.text()` (`chat.js:3146–3154`), message text nodes (`chat-renderer.js:105–179`), guest Temporary label (`chat.html:230`).

### Native + GPU + infra
- SEC-003 confirmed interface: `NativeSecureKeyPlugin.java:41,218–229,346–415` exposes `getKey`, caches `unlockedKeys` on cached login; uncached path also returns key (`:248–273`). Bridge reachability needs APK proof. Fix → SEC-010.
- Keystore fallback (`:577–590,658–695`, `:280–285`): explicit fail-open; decide fail-closed → part of SEC-010 decision.
- Resume/overview edges (`MainActivity.java:50–58,169–211,366–385,476–480,525–535`): needs device proof; do not claim leaks statically.
- Auto `ALLOW_ALL_HOSTS_VALIDATOR` (`car/ChatbotCarAppService.java:28–32`, DHU-only per `mobile-apps.md`) + unauthenticated car posts (`car/VoiceScreen.java:330–426`): defer host allowlist; red-first protected-server test for transport.
- COR-002 TTS exhaustion (`NativeVoiceTtsPlugin.java:197–267`): settle pipeline contract first.
- Car content/token file logging confirmed: `car/VoiceScreen.java:298–309,391–417` → `util/FileLogger.java:24–67`, crash bundle includes lines (`util/ClientLogReporter.java:95–97,119–140`). Fix → SEC-009.
- Voice backend unauth (`chatbot-cuda/src/main.py:90–164`) matches internal-API intent (`design.md:209`) on isolated Compose net (`docker-compose.yml:4–40`); defer pending topology proof.
- DNS no-auth upstream (`dns/forwarder.py:173–344`): defer unless adversarial resolver in scope.
- Helm `secretEnv` literal (`deploy/helm/chatbot/values.yaml:21–27`, `templates/webserver-deployment.yaml:39–44`): fix → SEC-011 (chart-render regression; operator coordination for migration).

## Triaged batches
- SEC-004: warm-cache key authentication (core history/api + cache).
- SEC-005: SEC-002 live-session gate + client-log `source` sanitization.
- SEC-006: provider/search content-log redaction (xAI, OpenAI error preview, Brave query).
- SEC-007: TTS admission permit held through token insertion.
- SEC-008: browser login stale-key clear + forget-then-claim + Standard-mode label.
- SEC-009: car voice content/token file-log removal.
- SEC-010: SEC-003 `getKey` export removal + keystore fail-closed decision (needs APK bridge proof).
- SEC-011: Helm secret-reference support (chart-render regression).
- Deferred with rationale above: SEC-001 ingress contract, logout GET contract, legacy PRF, Auto host allowlist, voice-backend auth, DNS transport, DOC-001/002 wording (DOC pass), COR-001/002/003 (separate correctness follow-ups outside the seven passes, as in phases 1–3), PERF-001 (Perf pass).

## Sessions 076–078 — implementation, 2026-09-29

All batches below carried red-first regressions and targeted green gates; workers did not commit. Primary reviewed each diff and committed.

- SEC-004 `f205030`: warm history-cache hit authenticates the request key against the sealed version-bound manifest (`history/api.rs:199–205`); new `history_cache_key.rs` (wrong key fails warm + cold). Red job `20260929T005221-25e21083f71e` (1 failed); green `20260929T005428-4dcbe5d9797c` (1), snapshot `20260929T005554-ed9a416963f4` (7), history lib `20260929T005601-84845156c434` (87).
- SEC-005 `137d79e`: client-log upload without CSRF requires live session (`client_logs.rs`, `identity.rs:has_live_session`); `source` sanitized before logging. New `client_logs.rs` regressions (6). Approved update of `router_identity_isolation.rs` pinning (unknown cookie 401; rate-limit fallback still 401,401→429). Green `20260929T010056-ae549d4f06bd` (6), `20260929T010107-ca79859bb989` (6).
- SEC-006 `32b1f6d`: xAI request-body/raw-chunk logs removed; OpenAI/xAI error bodies replaced with status-only errors; Brave query no longer logged. New `provider_log_privacy.rs` sentinel regressions (2). Approved update of two OpenAI unit assertions to status-without-body. Green `20260929T010305-cc8de5a42d1d` (2), openai `20260929T010357-5d6b0af3708e` (12), xai `20260929T010410-b3ef3aa433e6` (4).
- SEC-007 `4df1041`: `POST /tts` holds the admission content permit through token insertion (`tts.rs`), dropping only once the token is visible to mode-change invalidation. New `voice_privacy.rs` barrier regression. Red `20260929T010721-d068052e4d8d` (delayed GET 200 instead of 404); green `20260929T010844-6ea70fc24c89` (1), voice_privacy `20260929T010937-c32df4edb5e4` (10), tts `20260929T011034-725a2bbde1f0` (15).
- SEC-008 `d812d3f`: login clears stale `storage_key` per attempt; both forget flows require successful `/login/forget` before claiming revocation; privacy selector offers Private/Non-private only with corrected copy. New `sec008_browser_ui.rs` (4). Red `20260929T010643-dfc0acd56ea4` (4 failed); green `20260929T010806-5284c808ca75` (4), js_syntax 11, client_derivation 3, remember_login 28, set_privacy 1.
- SEC-009 `307230b`: car-turn `FileLogger` content/token calls removed from `VoiceScreen.java` (transcription, response/excerpt, TTS text, token, bodies); status codes kept. Rust distribution source pin added. Red `20260929T011456-bea12dd3eecd` (1 failed); distribution `20260929T011601-326bb2a794c9` (13); APK `20260929T011644-f084209b301a` (72 tasks). Backup/external-storage reachability of historical logs needs physical-device proof.
- SEC-010 `9f663ec`: JS-callable `getKey` export and its wrapped-key reader removed; cached login rejects when biometric/device-credential unlock is unavailable; wrapping-key creation no longer falls back to non-auth-bound keys. Caller grep found no in-repo production JS/Android caller (`enc-key.js` matches are separate functions). Approved update of `credential_sealed_storage.rs` legacy-API pin. Red `20260929T012033-bccf03b4e028` (1 failed); distribution `20260929T012205-c3b45563c749` (15); credential `20260929T012245-0ac180fafc4c` (3); APK `20260929T012301-cf905498007b` (72 tasks). Loaded-page bridge reachability + unavailable-gate login flow need physical-device proof.
- SEC-011 Helm `secretEnv` literals: DEFERRED — `helm` unavailable in sandbox and no repo-runnable chart render test exists; no chart changes made (worker stop-report). Concrete regression proposed for a Helm host: `secretEnv` accepts `valueFrom.secretKeyRef`, literal secrets rejected; render asserts Deployment/ConfigMap contain the ref and never the literal `SEC011_LITERAL_SENTINEL`; log under `temp/test-logs/sec011-*.log`. Operator migration of existing literal values required before deploying such a change.

## Final gate, 2026-09-29

SEC-005 follow-up updated `router_resource_isolation.rs` + `tts_rate_policy_isolation.rs` (unknown-cookie 204→401, 429 shapes unchanged): green `20260929T013446-80d0e63fc223` (4), `20260929T013555-b7e32f2884c5` (9). First full workspace suite on that tree (`077ca9e`): job `20260929T013620-393dd3eca2bc`, exit 0, untruncated. APK compile proven on SEC-009 (`20260929T011644-f084209b301a`, 72 tasks) and SEC-010 (`20260929T012301-cf905498007b`, 72 tasks) trees.

## Sessions 079–080 — larger-model rework, 2026-09-29

The completion review found a Standard-mode regression, a CSRF-config bypass, missed TTS text logs, string-only verification, and open race/Helm dispositions. All five reworked with red-first regressions; workers did not commit, primary reviewed each diff.

- SEC-008 rework `6d043a1`: Standard restored as selectable (template option, `SELECTABLE_PRIVACY_LEVELS`, per-level confirmation copy) with the eligibility lattice unchanged; stale `storage_key`/forget gates kept. `design-privacy.md` Standard lines corrected to implemented behavior. Source-position tests replaced with Node-executed regressions (`fixtures/sec008_browser_ui.js` on `vm`: login retry, forget failure, logout, privacy selection). Red `20260929T020245-d2b95d5feb72` (1 failed on missing Standard); green `20260929T021131-ee930c5283b7` (4), js_syntax 11.
- SEC-005 hardening `b5bf0f7`: `/client_logs` requires a live session with or without a CSRF header; a presented token must also validate (`client_logs.rs`). New `csrf:false` bypass regressions. Red `20260929T020009-388f9d0d75ac` (3 failed, bypass observed 204); green client_logs `20260929T020942-1a38de2f3432` (7) plus identity/resource/rate-policy targets 6/4/9 with no existing-test changes.
- SEC-006 follow-up `983932c`: `tts/text.rs` content logs replaced with lengths/counts; in-file tracing regression with sentinel speech/URL/number. Red `20260929T020251-9da9114180c3` (1 failed); green `20260929T020547-9fbb4ba4a544` (1), lib `20260929T021023-fc9cfe989704` (79).
- Native executing verification `3102f59`: framework-free `NativeUnlockGate.canPrompt` extracted and executed on JVM (`NativeUnlockGateTest` via javac/java); store harness now compiles the real `CredentialCookies` and executes selection/purge/expiry. Per-pin accounting in worker return; `SealedCredentialPayload` codec, key-return absence, and full prompt flow remain source-level + APK. Green distribution `20260929T020258-f30634a3fbca` (16), credential `20260929T020501-2a354b4efabf` (3), APK `20260929T020635-9a542a4afebd` (72 tasks).
- Races closed `fbf0f6d`: remember rotation/peek/both revocations require the current bearer secret (forged-cookie red first); verifier/salt first-enrollment is first-wins via atomic `publish_once` (hard-link). New `remember_family_authorization.rs` (3) + `user_store_first_enrollment.rs` (2); lib 185/185, account_store_inputs 5/5.
- SEC-011 `4ac64e1`: `secretEnv` renders `valueFrom.secretKeyRef` and fails on literals (Helm v3.17.3 downloaded to sandbox); lint + reference-render + `SEC011_LITERAL_SENTINEL` rejection green (`sec011-final.log`). Operator must create the referenced Secret before installing.

## Final gate, 2026-09-29 (rework tree)

Full workspace suite on the closing tree (`4ac64e1`): job `20260929T021608-ac28509ccdcd`, exit 0, untruncated, 127 ok suites, 1018 passed / 0 failed; log `temp/test-logs/phase4-final-20260929.log`. APK compile proven on the SEC-009/010 and rework trees (72 tasks each); Rust production changes after the last APK build are remember/user-store, client_logs, tts/text (server, covered by the suite) — no new native code paths except `NativeUnlockGate` (pure Java, JVM-executed). Device-proof limits stand: car-log historical reachability, loaded-page bridge reachability, on-device unavailable-gate login. Static assets need a host webserver rebuild/restart to deploy. Open leads remaining: SEC-001 ingress contract, logout-GET contract, legacy PRF decision, Auto host allowlist, voice-backend topology, DNS transport, COR-001/002/003 (separate correctness follow-ups), DOC wording (DOC pass), PERF-001 (Perf pass). Phase 4 implementation is ready for re-review.

## Sessions 081 — second rework + ledger reconciliation, 2026-09-29

- Remember coherence `3e058bb`: `resume()` returns Invalid on secret mismatch with no family deletion (the old theft-revocation deleted via unauthenticated `GET /`); `revoke_if_username()` accepts current or previous-generation secret so rotation-then-forget succeeds; module docs updated; two stale `revokes_family` test names renamed to the fail-closed behavior. Supersedes the session-075 C03 replay-policy note above. Red `20260929T023605-9b8770dbeac0` / `20260929T023652-ca65e0e55272`; green core `20260929T023836-0a9a09fc8247` (4), server `20260929T023920-466e3c0aa198` (31), lib 13.
- Unlock execution `7b1eac4` + `8045092`: the real `NativeSecureKeyPlugin.unlockCachedLogin` runs on JVM against fake Activity/BiometricPrompt/CookieManager/keystore — unavailable/cancelled/failed auth rejects with no decrypt or injection; success injects four HttpOnly cookies with `unlocked:true` and no key field; tampered payload rejects. `org.json` runs as a documented flat-map stand-in (real JCE AES-GCM). Trivial equality fixture replaced. Green distribution `20260929T023910-da8da5138885` (16), credential targets, APK `20260929T024043-ff2c39e9e1ef`.
- Ledger: Sec column filled per unit in `coverage.md` (R: C07/S11/T03/W02/W03; B: V01/S07/N04/O03/D01/D02/R00; rest P with exact scope). Two read-only workers supplied per-file evidence and named backlog candidates with prerequisites; hardware/topology proofs recorded as accepted limits.

## Final gate, 2026-09-29 (sessions 081 tree)

Full workspace suite on the closing tree (`8045092` + ledger docs): job `20260929T024231-e9b69ff2ef81`, exit 0, untruncated, 127 ok suites, 1022 passed / 0 failed (panics in the log are `should_panic` config tests); log `temp/test-logs/phase4-final2-20260929.log`. Ready for re-review.

## Sessions 082 — gap closure round 2 + SEC-012, 2026-09-29

- SEC-012 `883e419`: OpenAI-compatible in-band SSE errors (HTTP 200) redacted to `HTTP 200 OK: upstream stream error` at construction, so neither logs (`search.rs` fallback `warn!`) nor client streams carry upstream text; no equivalent xAI path found. Sentinel regression covers direct + tool-aware streams. Red `20260929T031002-1312eb955d36` (1 failed); green provider `20260929T031133-5b47af34c4da` (3), openai `20260929T031214-04a12184c826` (12), xai `20260929T031227-605d98b3ec7b` (4). This also closes the S04 in-band-error candidate raised during the same round.
- Generic-cookie forget `570c2e2`: forget-only `peek_username_for_forget` accepts current-or-previous secret, matching revocation; strict `peek_username` kept for login/enc-key callers per audit. Route regression uses only the rotated-out generic cookie (`revoked:true`, family gone, clear-cookies emitted); forged generic cookie stays `revoked:false` with the family intact. Red `20260929T025843-881fda671a76` (1 failed); green remember_login `20260929T025946-bc307cccab5a` (33), family `20260929T030133-2e7121cb9120` (4), lib 13.
- Gap closure reads (read-only, no new batches): browser round closed W01 (sink-driven + earlier reads), W04 (all templates/styles/substitutions), W05 (four remaining modules + nine earlier reads) to R; native round closed N01/N02/N03/T04-test-scope to R with switch-concurrency, enqueue-origin, and resume-lock backlog items; verification round closed R01/C01–C06/C08/C09/P01/S04/S08/X01/G01/O01/O02 to R with complete 1→EOF accounting, and mapped every Phase-4 fix to its regression body (T01/T02 stay P for assertion-level scope). New backlog candidates recorded in the coverage note above.

## Final gate, 2026-09-29 (sessions 082 tree)

Full workspace suite on the closing tree (`e2c66af`): job `20260929T031346-2a1c5b00855f`, exit 0, untruncated, 127 ok suites, 1025 passed / 0 failed; log `temp/test-logs/phase4-final3-20260929.log`. Ready for re-review.

## Sessions 083 — resume-lock, token-log fixes + ledger completion, 2026-09-29

- Resume lock `1ef1eb0`: `promptResumeUnlock` routes unavailable authentication through the JVM-tested `NativeUnlockGate` — logs and stays locked with the retry overlay instead of `unlockApp()`; first-run/no-session path unchanged. JVM-executed unavailable/cancelled/failed/success cases (`ResumeUnlockGateTest`) + routing pins. Red `20260929T032632-313e05fba8f7` (2 ran); green distribution `20260929T032848-007b5801bde8` (19); APK `20260929T032942-e1643b9c3b2d`.
- Token-log fixes `1ef1eb0`/`a63c3b6`: TTS playback logs code-only (no URL); 5xx middleware uses prefix-scoped `sanitize_log_path` (`/tts_stream/{token}` → `[REDACTED]`, other paths byte-identical); STT INFO log drops the caller filename, keeping bytes/content-type/compressed telemetry. Captured-log regressions with sentinels for allowed + denied uploads. Red `20260929T032750-aee8dbd7bb08` / `20260929T032811-4d4089aa6599`; green sanitizer `20260929T032936-7b28af09f7b7` (2), sttname `20260929T032901-ab9c5c0c4206` (1).
- Ledger: the 16 remaining `P` application units advanced to `R` on completed reads (S01/S02/S03/S05/S06/S09/S10/S12, W01/W04/W05, N01/N02/N03, O01/O02); per-unit ranges in the coverage note above. Sec `R` now covers every application unit except T01/T02/T04 (security-regression bodies; assertion audit is test-quality scope).
