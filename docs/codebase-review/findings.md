# Cross-pass findings

| ID | Owner pass/file | Finding | Current status |
| --- | --- | --- | --- |
| MOD-001 | Phase 1 — [modularity.md](modularity.md) | Core session APIs retain HTTP-shaped serialization/error ownership. | Remains tracked; no final disposition recorded. |
| MOD-002 | Phase 1 — [modularity.md](modularity.md) | Session identity lifecycle and chat orchestration have distinct but incompletely separated ownership. | Remains tracked; no final disposition recorded. |
| MOD-003 | Phase 1 — [modularity.md](modularity.md) | Server route/configuration inputs retain ambient ownership. | Partially remedied; remaining ambient policies are tracked in [modularity.md](modularity.md). |
| MOD-006 | Phase 1 — [modularity.md](modularity.md) | Generation settlement and durable/mirror mutation lifecycles have multiple owners. | The leased acquired-entry/locked-purge expiry case is resolved; direct compatibility APIs and selected pre-prepare settlement semantics remain open in [modularity.md](modularity.md). |
| MOD-009 | Phase 1 — [modularity.md](modularity.md) | Browser application state crosses DOM/global initialization and lifecycle responsibilities. | Implemented; follow-ups verified in [modularity.md](modularity.md). |
| MOD-012 | Phase 1 — [modularity.md](modularity.md) | Android voice lifecycle crossed plugin and duplicate event paths. | Session coordinator implemented; device validation is not claimed; see [modularity.md](modularity.md). |
| MOD-015 | Phase 1 — [modularity.md](modularity.md) | Voice-service settings and inference lifetimes were ambient. | Settings and lifespan-owned inference implemented; streaming/runtime limits remain open in [modularity.md](modularity.md). |
| MOD-017 | Phase 1 — [modularity.md](modularity.md) | Native origin, build inputs and deployment configuration had several owners. | Flavor-origin ownership established; generation/deployment mismatches remain open in [modularity.md](modularity.md). |
| COR-001 | Correctness follow-up — [test-quality.md](test-quality.md), TQ-004 | Concurrent user-store read/modify/write operations may lose updates. | Fixed for ordinary in-process writers by the canonical-path lock across load/modify/save (TQ-004). The distinct first-open initialization race tracked as PR-015 now uses non-replacing atomic initialization; this does not promise cross-process read/modify/write serialization. |
| COR-002 | Correctness follow-up — owner not specified in this ledger | Native TTS resource exhaustion needs a settled pipeline contract. | Separate correctness follow-up; pipeline contract remains prerequisite. |
| COR-003 | Correctness follow-up — [findings.md](findings.md) | History reads may combine independently acquired database snapshots. | Confirmed by source; deterministic reproduction and implementation scope decision pending. |
| TEST-001 | Phase 6 — [test-quality.md](test-quality.md) | Fixture reset may not isolate process-global services across repeated workspaces. | Fixed: the 20 identified multi-workspace server test binaries use owned per-workspace composition; direct helpers use matching `AppServices`. Explicit custom-injection and deliberate global-compatibility coverage remain. The isolation regression and final full gate passed; see [test-quality.md](test-quality.md#findings). |
| TEST-002 | Phase 6 — [test-quality.md](test-quality.md) | Test-quality cross-pass item. | Fixed in the Phase 6 follow-up; see [test-quality.md](test-quality.md#findings). |
| TEST-003 | Phase 6 — [test-quality.md](test-quality.md) | Test-quality cross-pass item. | Fixed in the Phase 6 follow-up; see [test-quality.md](test-quality.md#findings). |
| TEST-004 | Phase 6 — [test-quality.md](test-quality.md) | Test-quality cross-pass item. | Fixed: template tests deleted. |
| TEST-005 | Phase 6 — [test-quality.md](test-quality.md) | Test-quality cross-pass item. | Fixed in the Phase 6 follow-up; see [test-quality.md](test-quality.md#findings). |
| SEC-001 | Phase 4 — [security.md](security.md) | Cookie transport classification depends on proxy-header trust and supported ingress behavior. | Open pending ingress/proxy-trust contract and dynamic validation. |
| DOC-001 | Phase 7 — [documentation.md](documentation.md) | Privacy terminology may overstate the implemented trust boundary. | Fixed: docs state "not end-to-end, as close as the stack allows"; see [documentation.md](documentation.md#resolution). |
| DOC-002 | Phase 7 — [documentation.md](documentation.md) | Documentation wording may diverge from history-cache key/TTL behavior. | Fixed in code: background sweep of expired cache entries plus zeroize on drop; see [documentation.md](documentation.md#resolution). |
| DOC-003 | Phase 7 — [documentation.md](documentation.md) | Documentation wording requires implementation-alignment review. | Fixed: history-store doc rewritten to match the code; see [documentation.md](documentation.md#resolution). |

## Ownership notes

COR-001 and COR-002 are listed as separate correctness follow-ups in [security.md](security.md); their dedicated owner file is not named in the source ledger. DOC-001–003 and TEST-001–005 are owned by the linked pass files. Other phase findings remain in their respective review ledgers.

## Post-refactor findings

[post-refactor.md](post-refactor.md) remains the evidence report for PR-001–022, the new/missed findings from the whole-codebase review at `6c86a98` and the subsequent user-reported oversized-image inference failure. It distinguishes reproduced behavior, the actual CI scanner failure, user reports, source-confirmed paths and outstanding device/concurrency verification. This cross-pass ledger records the current COR-001 and MOD-006 dispositions; the report preserves the original review snapshot and adds the dated remediation record. Final integrated gate `20261004T061453-813f3ffc3d50` passed: 153 nonzero Rust result blocks, 1,199 passed, 0 failed; nested DNS (34) and voice-service (72) Python tests are reported separately. PR-006's header-free legacy Brave fallback edge and device/GPU/heap limits remain open; a green gate is not an all-findings-closed disposition.
