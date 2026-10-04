# Modularity review (Phase 1)

Scope: ownership and lifecycle boundaries across handwritten application code and test boundaries. Phase 1 is complete for the authorized scope; generated, protected and external materials retain the exclusions in [coverage.md](coverage.md).

## Findings

| ID | Location | Finding | Final disposition |
| --- | --- | --- | --- |
| MOD-001 | `chatbot-core` session/history; [findings.md](findings.md) | Session operations and history persistence have coupled ownership boundaries. | Remains tracked in [findings.md](findings.md); no final disposition recorded here. |
| MOD-002 | Application composition; [findings.md](findings.md) | Application state and dependencies have multiple owners. | Remains tracked in [findings.md](findings.md); no final disposition recorded here. |
| MOD-003 | `chatbot-server` services/configuration | Process-global state bypassed application composition. | Partially remedied through owned `AppServices`, account/chat/session/history/token/rate services, `ConfigSource` and generation/policy dependencies; other route/config policies and fake inputs remain ambient. |
| MOD-004 | `chatbot-core/src/names.rs`, `fernet_crypto.rs`, `legacy_sets_json/` | Migration-only storage owned live naming and crypto rules. | Fixed: shared naming and Fernet helpers moved to current-domain modules; legacy compatibility remains. |
| MOD-005 | `chatbot-core/src/history/` | History facade exposed bypasses and ambiguous logical/materialized snapshots. | Facade exports/writer/cache bypasses narrowed; private `LogicalSnapshot` now normalizes cache representation. Public `SetSnapshot` remains a compatibility DTO. |
| MOD-006 | `chatbot-core` session and history mutation paths | Generation settlement and durable/mirror mutation lifecycles had multiple owners. | Leases bind the acquired session entry; expiry purge retains locked entries, preventing settlement from being redirected by purge/recreation. Typed finalization and owned durable-then-mirror operations are implemented. Direct compatibility APIs and selected pre-prepare saved-error-turn semantics remain separate/open. |
| MOD-007 | `chatbot-server/src/providers/` | Route handlers owned provider dispatch and search policy. | Shared closed-enum dispatch and provider-neutral message module implemented; comprehensive provider-neutral redesign remains open. |
| MOD-008 | `chatbot-server/src/request_context.rs`, `enc_key_cookies.rs` | Request identity, key validation and cookie policy lacked clear adapters. | Raw request and encryption-cookie adapters implemented; guest-capable verified data context added. Session/remember ownership remains distinct; SEC-002 is separate. |
| MOD-009 | `static/` browser request, playback, voice and credential modules | Browser application state was coupled to DOM/global initialization and lifecycle responsibilities. | Implemented across conversation/session/voice-text/voice-lifecycle/playback and credential modules; follow-ups MOD-009-A/B verified in sessions 047–048 and completion review 052. |
| MOD-010 | Browser stream decoder; server protocol consumers | Stream protocol interpretation had multiple independent owners. | Browser incremental decoder/projection centralized with existing wire behavior; cross-language text/status/TTS consumers and typed wire events remain separate. |
| MOD-011 | `chatbot-server/src/tts/` | TTS token lifecycle, synthesis, text processing and HTTP were interleaved. | Text, backend PCM and token-store boundaries extracted; HTTP/access/codec remain in parent. |
| MOD-012 | Android voice lifecycle and foreground service | Android voice lifecycle crossed plugins and duplicate event paths. | Session coordinator and truthful serialized stop outcomes implemented; device validation is not claimed (MOD-012-A verified in session 052). |
| MOD-013 | `android/app/.../car/` | Android Auto implemented a separate workflow with divergent server protocol/lifecycle. | Deferred pending a supported Auto contract; protocol/session/CSRF repair is not part of the completed modularity scope. |
| MOD-014 | `enc-key.js`, Android credential plugin | Credential-cache APIs retained obsolete key-returning responsibilities. | Metadata/crypto and sealed-cookie codec boundaries extracted; the legacy key-export surface has been removed. SEC-003 remains deferred as a distinct security decision. |
| MOD-015 | `chatbot-cuda/src/` | Voice-service settings and inference lifetimes were ambient. | Settings and lifespan-owned inference service implemented; non-streaming job/resource ownership verified in session 052. Streaming cancellation/backpressure and GPU/device behavior remain unverified. |
| MOD-016 | Rust/JS/native test boundaries | Tests depended on source/layout rather than stable behavior boundaries. | Stable-unit and behavior seams partially added; broader source-pinned suites and harness consolidation remain for Phase 6. |
| MOD-017 | Native origin, build inputs, deployment configuration | Distribution settings and generated build inputs had several owners. | Flavor-origin ownership is established; clean-checkout generation inputs, Helm/readiness and STT-setting alignment are not recorded as fully resolved. |

## Cross-pass items

Owned elsewhere: COR-001, COR-002, COR-003 and SEC-002, SEC-003 in [findings.md](findings.md); DOC-002, DOC-003 in [documentation.md](documentation.md); PERF-001 in [performance.md](performance.md); TEST-001, TEST-002, TEST-003, TEST-004, TEST-005 in [test-quality.md](test-quality.md); OPS-001 in [boundaries.md](boundaries.md).

## Decisions

- Keep compatibility surfaces such as public `SetSnapshot`, legacy APIs and provider DTO re-exports when they preserve callers/contracts.
- Prefer cohesive owners and explicit dependencies; do not add traits/frameworks or services solely to satisfy abstraction goals.
- Keep route-specific saved-turn/append-versus-replace behavior, privacy and error ordering, and desktop/native policy distinctions explicit.
- File size alone does not justify splitting; preserve migration support and established storage/protocol contracts.

## Open items

- MOD-001/002 remain in [findings.md](findings.md); this ledger records no later final disposition.
- MOD-003 retains ambient route/config inputs; MOD-006 retains direct compatibility APIs and selected pre-prepare settlement semantics; MOD-007 retains broader domain redesign; MOD-013 waits on an Android Auto contract.
- MOD-015 streaming cancellation is cooperative and cannot stop in-flight GPU inference; GPU/device behavior remains unverified. MOD-016 broader test-quality work is deferred; MOD-017's generation/deployment mismatches await their owning follow-up.
- Cross-pass items above remain with their owning review files; COR-003 and Android Auto protocol repair are not silently included in modularity work.

## Completion

Phase 1 completion review: session 052, reviewed at `d55ee5d`; four follow-ups MOD-009-A/B, MOD-015-A and MOD-012-A verified. Final full suite: job `20260919T202846-0908e2daba66`, exit 0, untruncated; exact counts are not recorded in this file's latest completion section. Recorded 2026-09-19. No phone, vehicle or GPU runtime validation claimed.
