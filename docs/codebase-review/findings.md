# Findings

Session 017 further narrows MOD-001: prepare-time history errors are typed, including minimal conflict metadata and the prepare-specific missing-set classification. Eight new route/mapper tests pass; primary corrected raw-400 logging-field parity before the final green suite. Encryption/store/init response carriers and finalizer rendering remain open.

Session 016 further narrows MOD-001: generation contention and premium access rejection are typed core outcomes with server-owned 429/403 rendering. Nine new before/after route tests and the full suite pass; history/storage and other `ServiceResponse` carriers remain open.

Evidence revision for session 001: `4cda3039d3e5a58932a3c40afccc1e4ce33a19e3`. No finding below is approved for implementation, fixed, or dynamically reproduced. Structural findings are based on inspected source; cross-pass leads explicitly retain uncertainty.

The continued modularity review is in [modularity.md](modularity.md): MOD-003 through MOD-017, extensions to MOD-001/MOD-002, and separately labeled correctness/security/testing/documentation follow-ups. Review coverage and execution limits are in [coverage.md](coverage.md). IDs are global across these records.

## MOD-001 — Core session APIs own HTTP serialization

**Further partial remediation (session 012):** five prepare-input validation categories are typed, with a server mapper and preserved saved-turn handling. `PrepareError::Service` carries remaining responses. Ten new characterization tests and the reviewed full suite pass; this does not close the broader core/HTTP coupling finding.

**Partial remediation (session 011):** encryption-key validation now returns `EncryptionKeyValidationError`, with direct server callers using one HTTP mapper. Core orchestration retains `require_encryption_key`'s `ServiceResponse` compatibility adapter. Exact rejection messages, verifier behavior, logs and error counting are preserved, verified by pre-extraction HTTP characterization and the corrected full suite. Other HTTP-shaped core outcomes remain open; see the session-011 checkpoint for regression evidence.

**Disposition:** confirmed. **Priority:** P2. **Confidence:** high for boundary coupling. **Units:** C02, R01, S01/S03 consumers.

**Evidence:** `chatbot-core/src/session.rs:38–43` defines `ServiceResponse` as numeric HTTP status, string headers, and body bytes; lines 520–549 serialize JSON and select HTTP statuses. Key-validation helpers return this response type (633–671), and `chat_prepare` returns it on failure (760–830). `chatbot-server/src/lib.rs:309–363` revalidates statuses/headers and builds an Axum response; `chat.rs:186–203` consumes this path. Independently, `chatbot-server/src/http_error.rs` already maps typed core errors into HTTP, including `HistoryError` at 86–110. That core error enum explicitly delegates HTTP mapping to the server (`history/api.rs:34–51`).

**Consequence:** the crate dependency direction is clean, but session policy is coupled to the wire representation. Callers must interpret response bytes/statuses rather than typed failures, and transport error policy has two owners. This is a maintainability problem, not a demonstrated response bug.

**Proposed correction:** after auditing all consumers, define narrow typed session/application errors and adapt them at the server boundary, following the existing history-error pattern. Keep externally visible statuses, JSON fields, messages, headers, and streamed error behavior stable. Do not move all session code merely to eliminate a type name.

**Verification needed:** behavior coverage for invalid/missing key, invalid request, denied model, concurrent generation, history conflicts, and server failures, including chat's saved-error-turn behavior. Inspect existing tests first and add only missing behavioral cases; test typed core outcomes and HTTP mappings at their appropriate layers.

**Dependencies/open questions:** complete C02 and every `ServiceResponse` consumer, especially `chat_utils`, memory/sets/preferences/reset and regeneration. Coordinate with MOD-002 so structural moves and type changes remain separately reviewable. **Fix/verification:** none yet.

**Session 002 update:** C02 and those production consumers have now been read. `chat_utils::service_error_message` deserializes the core response body back into a message, confirming the unnecessary serialization boundary. Existing wire differences are real contracts to characterize before consolidation: session history `NotFound` maps to 400, while the general history HTTP mapper uses 404.

## MOD-002 — Session module mixes identity lifecycle with chat application orchestration

**Further partial remediation (session 015):** HTTP identity store, lifecycle and DTOs moved to `session_identity.rs`; compatibility re-exports and the combined purge entry point remain in `session.rs`. Six new lifecycle tests passed before and after the verbatim move, along with the full suite. Chat orchestration and global service composition remain open; expiry and generation-lock semantics are unchanged.

**Partial remediation (session 013):** prompt packing accepts a small borrowed `PromptInput` rather than reading `ChatContext`. The public session-context wrapper remains for compatibility and resolves provider defaults. Seven new boundary tests and the full suite pass; existing prompt tests supplied the pre-extraction baseline. Session identity, lifecycle and orchestration separation remain open.

**Disposition:** confirmed. **Priority:** P2. **Confidence:** high for mixed responsibilities; final extraction boundaries pending. **Units:** C02, R01, S01.

**Evidence:** `session.rs` owns cookie parsing/building, CSRF, login/logout and HTTP-session lifetime (133–416); chat state and generation locks (418–518); key-verifier/store access and model-tier policy (633–735); chat preparation including durable prompt updates (760–938); and authenticated durable commits/guest append plus user-facing stream errors (940–1055). The same public module is used by server startup cleanup, the home handler, and chat preparation.

**Consequence:** changes to identity/session mechanics and changes to chat persistence/orchestration meet in one module and state API. The observed problem is responsibility coupling, not simply a long file. Cookie-session tests and chat-lifecycle tests also have to navigate independently initialized global state.

**Proposed correction:** finish tracing regeneration and state mutation first; identify a small internal split between HTTP identity/CSRF sessions and chat application preparation/commit. Preserve compatibility exports if useful during migration. Keep durable writes through `HistoryService` and preserve a single owner for generation-lock lifetime. Avoid introducing a framework or new crate without a demonstrated need.

**Invariants/verification:** guest isolation; authenticated account identity; login rotation/logout semantics; data-key checks; durable capture/conflict behavior; cancellation and disconnect cleanup; no lost or duplicate finalization; expiry behavior. Establish adequate existing integration coverage and focused unit seams before changes.

**Dependencies/open questions:** unreviewed regeneration and mutation APIs, stream guards, expiry tests, and history design. MOD-001 can be related without becoming a single large rewrite. **Fix/verification:** none yet.

**Session 002 update:** production regeneration/mutation/guard paths and both history designs have now been read; MOD-006 records the lifecycle issue more precisely. The pure prompt packer in `chatbot-core/src/chat.rs` also depends on the large session-owned `ChatContext`, forcing unrelated identity/provider/capture fields into its fixtures. A small prompt-input value is a useful extraction seam. Expiry behavior and full regression coverage still need characterization before implementation.

## TEST-001 — Fixture reset and global service lifetime may disagree

**Disposition:** needs investigation. **Priority:** provisional P2. **Confidence:** high for observed lifetime mismatch, unproven test failure. **Units:** T03, C01/C02/C04. Recorded during modularity; not testing-pass completion.

**Evidence:** `chatbot-test-support/src/lib.rs:68–95,103–115` changes cwd/environment, resets config/rate limiting, and restores cwd/environment on drop. `session.rs:153–163,471–481` captures configuration in globals that do not reset with `config::reset()` (`config.rs:208–213`). `history/api.rs:95–119` separately initializes a global history service from configuration.

**Question/consequence:** can multiple workspaces/configurations coexist or run sequentially in one test process and silently reuse the first configuration/data root? Callers may deliberately serialize or isolate processes; that must be inspected before calling tests flaky or wrong.

**Next evidence/possible correction:** audit fixture callers, test-process boundaries, environment locks, and reset expectations. If a real isolation problem exists, reproduce it with differing workspace roots/settings before selecting scoped injection, owned services, or explicit process isolation. Do not recommend resetting live global stores indiscriminately. **Fix/verification:** none yet.

**Session 002 update:** Cargo integration files provide process boundaries between binaries; many files also use local mutexes within their process. That limits the claim: globals are not automatically shared across every integration file. However, repeated `TestWorkspace` creation within a binary still resets only some state, and the public fixture itself does not enforce serialization. `client_logs.rs` creates workspaces in two async tests without a local fixture lock. Runtime nondeterminism has not been tested, so this remains an isolation risk rather than a claim that a particular suite is flaky.

## SEC-001 — Cookie transport classification requires a proxy trust review

**Disposition:** needs investigation. **Priority:** unassigned pending trust-boundary evidence. **Confidence:** source observation only. **Units:** R01, O02, N04. Recorded during modularity; not security-pass completion.

**Evidence:** `chatbot-server/src/lib.rs:144–224` classifies transport using URI/Host and several proxy headers, then strips `Secure` from response cookies for requests classified as plain HTTP. Absence of Host/proxy headers receives different treatment, explicitly for in-process tests.

**Question/consequence:** validate these assumptions against actual ingress/proxy configuration and supported Android/LAN behavior. Header handling is security-sensitive, but this read alone proves neither an exploitable bypass nor an incorrect product requirement.

**Next evidence/possible correction:** inspect deployment ingress trust, cookie issuance, native loading requirements, and behavioral tests for direct HTTP, HTTPS termination, contradictory/untrusted forwarded headers, and multiple Set-Cookie values. Establish the intended trust model before proposing a correction. **Fix/verification:** none yet.

**Session 002 update:** inspected Compose/Helm use host networking by default; the actual TLS proxy configuration is external. `tests/login.rs:430–694` does exercise real local HTTP, HTTPS-forwarded-header cookie behavior, and stale-CSRF recovery. This confirms intended transport compatibility, not validation of the external proxy trust boundary.

## DOC-001 — Privacy terminology may overstate the implemented trust boundary

**Disposition:** needs investigation. **Priority:** provisional P2. **Confidence:** high for textual tension; implementation-wide claim review pending. **Units:** D02, C03/C04, S02.

**Evidence:** `docs/design-privacy.md:17–20` labels the default mode “Zero-Knowledge”; lines 75,79 call disk persistence “end-to-end encrypted.” The same document says the server receives the key and decrypts during requests (60–65,81), and supports server-side password derivation fallback (97). Inspected `session.rs:633–654,851–883` verifies the presented key and passes it to server-side history operations.

**Consequence/question:** readers may mistake encrypted-at-rest storage without a standing server key for protection against an actively compromised application server. Audit the full key lifecycle and intended threat model before settling replacement language.

**Proposed direction/verification:** use precise descriptions of storage encryption, request-time server access, idle-key handling, client derivation/fallback, and actual adversary assumptions. Check every security/privacy guarantee against implementation; distinguish implemented protections from planned modes. No cryptographic architecture change is implied by this documentation lead. **Fix/verification:** none yet.
