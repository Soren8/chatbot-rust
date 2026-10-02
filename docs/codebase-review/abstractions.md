# Abstractions / reuse review (Phase 3)

Scope: repository-wide review of bounded abstractions and duplication, with zero behavior change and targeted verification before a final full-suite gate. Phase 3 is complete for the agreed moderate scope; coverage is tracked in [coverage.md](coverage.md).

## Findings

| ID | Location | Finding | Final disposition |
| --- | --- | --- | --- |
| ABS-001 | `dns/forwarder.py` | DNS upstream filtering and relay preflight logic were duplicated. | Fixed in session 064; DNS tests 31/31 and full suite passed. |
| ABS-002 | Chat/regenerate and memory HTTP handlers | Prepare-error and mutation-mirror error mappings were duplicated. | Fixed in session 065; four targeted server suites passed. |
| ABS-003 | History crypto/ops/API | Media AAD, capture snapshot assembly and first-turn naming were duplicated. | Fixed in session 066 with two naming assertions; memory/prompt mirror sharing deferred due to post-durable/mismatch control-flow risk. |
| ABS-004 | OpenAI adapter, `session-client.js`, `credential-crypto.js` | Request setup, CSRF-header building and base64 decoding had identical shared logic. | Fixed in session 067; Kokoro warmup was deferred pending warmup-failure characterization, then addressed in ABS-007. |
| ABS-005 | `chat_images.rs`, Fernet crypto callers | Image-edit skeleton and constant-time equality logic were duplicated. | Fixed in session 069; direct helper test and core suite passed. |
| ABS-006 | Server request context, agent connections, page responses | Fallback resolution, mutation guards and page-response construction were duplicated. | Fixed in session 069; context, agent and page suites passed. |
| ABS-007 | Kokoro model loading; Android origin selection | Warmup logic duplicated; native origin delegation was explored. | Kokoro warmup fixed with characterization. Android delegation reverted because it violated the flavor-resource contract; per-consumer reads retained. |
| ABS-008 | Login notice, desktop retry, Android origin consumers | Client setter/retry behavior and native origin resolution had shared logic. | Fixed in session 071 with Node and javac-executed behavior fixtures; migrated assertions retained contract. |
| ABS-009 | Session orchestration | Prepare snapshot loading and history-clear mutation logic had reusable common steps. | Fixed in session 072; route-specific duties and durable operation differences retained. |
| ABS-010 | History operations | Content mutation and append/image-entry helpers had common logic. | Fixed in session 072; lock/reload and missing-image semantics preserved. |
| ABS-011 | Chat/regenerate handlers and xAI key selection | Provider-stream forwarding, saved-error response construction and fake-key handling had reusable paths. | Fixed in session 072; route-specific logging, append/replace and live-vs-explicit timing retained. |
| ABS-012 | Browser conversation state and credential metadata | Binding predicate and slot-key selection were duplicated. | Fixed in session 072; existing behavioral harnesses passed. |

## Cross-pass items

COR-003 in [findings.md](findings.md); MOD-010 in [modularity.md](modularity.md); MOD-017 in [modularity.md](modularity.md) records the flavor-origin constraint.

## Decisions

- Keep abstractions private and narrow; share identical steps, not whole flows with different persistence, lock, ordering or error semantics.
- Preserve caller-specific live-vs-owned configuration timing, compatibility surfaces, validation/error order, resource lifetimes and platform behavior.
- A completed unit/coverage cell does not mean issue-free; backlog candidates require focused characterization first.
- File size or superficial resemblance alone is not sufficient reason to extract or unify.

## Open items

- Deferred candidates await specific coverage/prerequisites: session memory/prompt mirror pairing (post-durable mismatch semantics); secure-flag choice (different config-read timing); coordinator release ordering tests; complete-clip merge (WAV/Opus and error differences, with chunking/truncation/cancellation coverage); button-style assertions; `ClientLogReporter` distinct null/error contract; legacy setters' direct tests; home defaults, token selection, cents conversion, home-model projection, service defaults and cookie-decoder behavior coverage.
- Cross-runtime voice-text/TTS stages, Java/Rust cookie transport and differing PCM-rate assumptions require interop characterization before merging.
- COR-003, Android Auto protocol repair and native key export remain with their owning passes.

## Completion

Phase 3 completion review for sessions 063–074 accepted all ABS-001–012 within the agreed moderate scope; S01's full read found no blocking defect or necessary extraction. Final full suite: job `20260928T225818-53da7826b56a`, exit 0, untruncated, 122 suites / 997 passed / 0 failed, plus 64 nested Python. Recorded 2026-09-28. Android compiled in session-071 physical-debug build (72 tasks); JS/DNS/CUDA deployment requires host rebuilds.
