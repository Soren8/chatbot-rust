# Abstractions / reuse / duplication review (Phase 3)

Scope (user-authorized): fresh repository-wide inventory, moderate bounded fixes with zero behavior change. Deferred items (COR-003, Auto protocol repair, legacy key export) stay out unless the duplication itself is in the touched code. Each batch carries targeted verification plus a final full green suite.

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

## Session 064 — ABS-001 implementation, 2026-09-28

Delegated to a worker with exclusive ownership of `dns/forwarder.py`; primary reviewed the diff and re-ran the gate.

- Extracted `_usable_nameservers(host_etc, host_run, host_abs)` — the exact non-loopback filter plus `[:MAX_UPSTREAMS]` cap, applied at the direct site and each stub fallback with identical order/behavior.
- Extracted `_query_txid(query, upstreams)` — the exact short-query/no-upstream guard plus TXID capture, shared by `forward_udp` and `forward_tcp`; transports and ordered failover untouched.
- Verification: `python3 -m unittest discover -s dns/tests -t dns` 31/31 OK (worker run plus primary re-run, per `dns/README.md` gate). Final full suite `temp/test-logs/abs001-full-20260928.log`: job `20260928T191728-ae8166f569a2`, exit 0, untruncated, 121 suites ok / 992 passed / 0 failed, including provider configuration checks.
