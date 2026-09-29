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
- Deferred with rationale above: SEC-001 ingress contract, logout GET contract, legacy PRF, Auto host allowlist, voice-backend auth, DNS transport, DOC-001/002 wording (DOC pass), COR-001/002/003 (COR pass), PERF-001 (Perf pass).

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
