# Simplicity review (Phase 2)

Scope: repository-wide simplicity review of handwritten implementation and relevant callers, preserving behavior, compatibility, ownership and error/configuration ordering. Phase 2 is complete for its authorized scope; coverage is tracked in [coverage.md](coverage.md).

## Findings

| ID | Location | Finding | Final disposition |
| --- | --- | --- | --- |
| SIM-001 | `chatbot-core/src/history/migration.rs` | Redundant migration branches handled the same missing-file and default-import outcomes. | Fixed in `088b6e0`; characterization and core tests passed. |
| SIM-002 | `chatbot-server/src/providers/generation.rs` | Nested XAI setup errors repeated fallback policy and cloned messages. | Fixed in `0804aee`; fail-closed fallback behavior retained and targeted tests passed. |
| SIM-003 | `static/chat.js`; conversation/playback fixtures | Redundant privacy refreshes and fixture drift obscured actual eligibility behavior. | Fixed in `ffae261`; real eligibility chain and playback gate fixtures used; review corrections verified in session 056. |
| SIM-004 | Core session/config/history operations | Expiry branches, provider cloning, word re-splitting and migration parent fallback were redundant. | Fixed in session 057; targeted tests and full suite passed. |
| SIM-005 | Server provider/generation/TTS operations | Unnecessary message clone, provider re-lookup and unused TTS destination snapshot were present. | Fixed in session 057; targeted tests and full suite passed. |
| SIM-006 | `static/chat.js`, `conversation-state.js`, `tts-playback.js` | Unused state/DOM iteration, misleading refresh alias, redundant binding checks and unused abort read added complexity. | Fixed in session 057; behavioral/targeted tests passed. |
| SIM-007 | Python audio, DNS, CI and dev Compose | Unused helpers/step, repeated DNS length summation and redundant override keys were identified. | DNS/audio/CI cleanup implemented; dev Compose pins restored in session 058 because literal pins intentionally shadow environment defaults. Final suite passed. |
| SIM-009 | Core/server/browser/Android/Python assets | Multiple bounded simplifications removed dead helpers, redundant conversions/mappers, and duplicated behavior. | Implemented in session 059; targeted checks, physical-debug build and final full suite passed. |
| SIM-012 | `chatbot-core/src/config.rs`; Android Auto | CSRF normalization and Auto import/output helper code had bounded simplifications. | Implemented in session 062; protocol/session/CSRF repair explicitly remains deferred. |

## Cross-pass items

COR-003 in [findings.md](findings.md); MOD-010 in [modularity.md](modularity.md). Android Auto protocol repair and native key export retain their owning-pass deferrals.

## Decisions

- Do not optimize line count or target a deletion count; require a concrete simplification without behavior loss.
- Preserve caller-specific error/saved-turn precedence, lock/order semantics, lazy live configuration reads, compatibility APIs, and desktop/native policy parity.
- Keep distinctions where error handling, timing, resource ownership or edge semantics differ; abstraction needs tests and real benefit.
- Retain public compatibility surfaces unless consumers/contracts are assessed; do not treat file size alone as a split criterion.
- Keep test-quality audit distinct; only alter a test contract when authorized and preserve behavioral coverage.

## Open items

No Phase 2 finding remains open. SIM-003's initial fixture deficiency was resolved in session 056. The CSRF normalization (SIM-012) and its verification are recorded; larger cross-pass items remain owned by their review files, not as simplicity blockers.

## Completion

Phase 2 completion verdict recorded on `refactor@40ac92f` in [README.md](README.md#passes-and-status), after SIM-001–012 and review fixes. Latest full-suite gate: session 062, job `20260928T080643-0e0c1b195846`, exit 0, untruncated: 121 suites / 992 passed / 0 failed, plus 63 embedded Python passed. Recorded 2026-09-28. Physical-debug APK job `20260928T080346-6397cd35a892` succeeded (72 tasks).
