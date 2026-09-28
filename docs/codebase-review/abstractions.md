# Abstractions / reuse / duplication review (Phase 3)

Scope (user-authorized): fresh repository-wide inventory, moderate bounded fixes with zero behavior change. Deferred items (COR-003, Auto protocol repair, legacy key export) stay out unless the duplication itself is in the touched code. Each batch carries targeted verification plus a final full green suite.

## Phase 3 closure (sessions 063–067) — ready for review

Focused duplication reads covered: `dns/forwarder.py` (full), prepare-error/mutation-error mappings (`chat.rs`, `regenerate.rs`, `memory.rs`, `chat_utils.rs` ranges + surroundings), history AAD/assembly/naming (`history/crypto.rs`, `history/ops.rs`, `history/api.rs` cited paths), `session.rs` mirror pairs (inspected, skipped), OpenAI setup (`providers/openai.rs` cited paths), `static/session-client.js` + `static/credential-crypto.js` (cited helpers), `chatbot-cuda/src/service.py` warmup (inventoried, skipped), Android origin/callers (inventoried, skipped for lack of Java unit coverage). Whole-unit exhaustive re-audits are not claimed; untouched units keep their prior state.

Implemented (all zero-behavior-change, targeted-green): ABS-001 DNS filtering + preflight; ABS-002 prepare-error + mutation-error mappers; ABS-003 media AAD + snapshot assembly + first-turn naming (with 2 new assertions); ABS-004 OpenAI setup + CSRF builder + base64 decoder.

Final full suite `temp/test-logs/abs004-full-20260928.log`: job `20260928T195247-760a5809b85d`, exit 0, untruncated, 121 suites ok / 994 passed / 0 failed (992 prior + 2 new naming assertions), including provider configuration checks. No Java changes (no APK rebuild); JS/DNS changes need a host webserver rebuild/restart and DNS sidecar rebuild to deploy.

Explicitly deferred with rationale (not forced into bounded batches): `session.rs` mirror-pair merge (needs control-flow changes around post-durable/mismatch handling), Kokoro warmup merge (needs new characterization test), Android origin-selection dedup (needs Java unit coverage first), COR-003/Auto protocol/key export (owning passes). Final full-suite evidence below.

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

## Session 064 — ABS-001 implementation, 2026-09-28

Delegated to a worker with exclusive ownership of `dns/forwarder.py`; primary reviewed the diff and re-ran the gate.

- Extracted `_usable_nameservers(host_etc, host_run, host_abs)` — the exact non-loopback filter plus `[:MAX_UPSTREAMS]` cap, applied at the direct site and each stub fallback with identical order/behavior.
- Extracted `_query_txid(query, upstreams)` — the exact short-query/no-upstream guard plus TXID capture, shared by `forward_udp` and `forward_tcp`; transports and ordered failover untouched.
- Verification: `python3 -m unittest discover -s dns/tests -t dns` 31/31 OK (worker run plus primary re-run, per `dns/README.md` gate). Final full suite `temp/test-logs/abs001-full-20260928.log`: job `20260928T191728-ae8166f569a2`, exit 0, untruncated, 121 suites ok / 992 passed / 0 failed, including provider configuration checks.
