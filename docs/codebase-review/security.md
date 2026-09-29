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
