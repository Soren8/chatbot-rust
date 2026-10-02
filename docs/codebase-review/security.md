# Security review (Phase 4)

Scope: repository-wide security/privacy review with bounded remediation; Phase 4 is complete for the reviewed scope. Static, JVM, APK, host and deployment evidence limits are distinguished below; this is not a claim of device, vehicle, biometric-hardware or GPU validation.

## Findings

| ID | Location | Finding | Final disposition |
| --- | --- | --- | --- |
| SEC-001 | `chatbot-server/src/lib.rs`; proxy ingress | Forwarding headers affect cookie transport classification and `Secure` removal. | Open: establish the ingress/proxy-trust contract and validate supported LAN/native behavior before changing compatibility. |
| SEC-002 | `chatbot-server/src/client_logs.rs`, `identity.rs` | Client-log upload had an incorrect live-session gate. | Fixed with live-session and presented-CSRF validation; regressions passed. |
| SEC-003 | Android `NativeSecureKeyPlugin.java` | Native bridge exposed cached credentials through a key-returning interface. | Fixed: removed JS-callable key export and required authentication-bound keystore unlock; JVM/APK verification passed. Physical-device flows remain unverified. |
| SEC-004 | `chatbot-core/src/history/api.rs`, `history/cache.rs` | Warm history-cache reads did not authenticate the supplied key. | Fixed: warm hits authenticate against the sealed version-bound manifest; wrong-key warm/cold regressions passed. |
| SEC-005 | `chatbot-server/src/client_logs.rs`, identity/CSRF handling | Client-log authorization and caller-supplied `source` were insufficiently constrained. | Fixed and hardened: live session is required with or without CSRF; any presented token must validate; source is sanitized. |
| SEC-006 | Provider/search/TTS logging | Logs could expose prompts, upstream error bodies, search queries, or submitted speech. | Fixed: sensitive bodies/text replaced by status, lengths/counts or fixed diagnostics; sentinel regressions passed. |
| SEC-007 | `chatbot-server/src/tts.rs` | Privacy permit ended before TTS token insertion, allowing a mode-change race. | Fixed: admission holds the permit through insertion; barrier regression passed. |
| SEC-008 | Browser login/forget and privacy selector | Retry could retain a stale key; forget could claim success before revocation; Standard-mode copy/selection diverged. | Fixed after review: clear key per attempt, gate success on forget response, and restore Standard as selectable with corrected copy and eligibility behavior. Executed browser regressions passed. |
| SEC-009 | Android Auto `VoiceScreen.java` | Car-turn logs included sensitive content and tokens. | Fixed: removed content/token file logging while retaining status codes. JVM/distribution and APK checks passed; reachability of historical external logs needs device proof. |
| SEC-010 | Android `NativeSecureKeyPlugin.java`, `NativeUnlockGate` | Key export and fail-open cached-login/keystore fallback weakened the unlock boundary. | Fixed: removed export and rejected unavailable authentication or non-auth-bound wrapping keys; JVM/APK checks passed. Loaded-page bridge reachability and on-device unavailable-gate flow remain unverified. |
| SEC-011 | `deploy/helm/chatbot` secret environment values | Literal secret values could be rendered into chart resources. | Fixed: chart supports `valueFrom.secretKeyRef` and rejects literals; Helm lint/render sentinel checks passed. Operators must create referenced Secrets before installation. |
| SEC-012 | OpenAI-compatible SSE error mapping | In-band upstream errors could expose upstream text in logs or client streams. | Fixed: redact to a status-only message at construction; direct and tool-aware sentinel regressions passed. |

## Cross-pass items

| ID | Owner |
| --- | --- |
| COR-001, COR-002, COR-003 | [findings.md](findings.md) (correctness follow-ups) |
| DOC-001, DOC-002, DOC-003 | [documentation.md](documentation.md) |
| PERF-001 | [performance.md](performance.md) |
| TEST-002, TEST-003, TEST-004, TEST-005 | [test-quality.md](test-quality.md) |
| OPS-001 | [boundaries.md](boundaries.md) |

## Decisions

- Do not alter cookie transport behavior based on source inspection alone; ingress trust and supported direct HTTP/LAN/native behavior must be established first.
- Preserve the GET logout/switch-account flow until its method/CSRF contract is decided.
- Preserve existing compatibility unless a security boundary and regression justify changing it; distinguish static/JVM/APK proof from live-device and topology proof.
- Keep server-side data-key use explicit: disk encryption does not imply the server cannot access request-time plaintext.

## Open items

- SEC-001 waits on the ingress/proxy-trust contract and dynamic validation of direct HTTP, TLS termination, contradictory/untrusted forwarded headers, and native/LAN requirements.
- Logout GET/CSRF waits on a switch-account contract decision.
- Legacy PRF unwrap waits on a legacy-support decision.
- Android Auto waits on supported host allowlisting and transport/authentication contract; no vehicle validation is claimed.
- Voice-backend authentication waits on proof of deployment topology; DNS upstream authentication waits on adversarial-resolver scope.
- Historical car-log reachability, loaded-page native bridge reachability, and unavailable-authentication login behavior wait on physical-device verification.
- COR-001–003, DOC-001–003, PERF-001 and TEST-002–005 remain with their owning passes above.

## Completion

Phase 4 completion review: session 084, 2026-09-29. Final full-suite job `20260929T043340-482ba1a11f9d`: exit 0, 127 Rust result blocks, 1,033 passed / 0 failed / 0 ignored, plus 64 Python tests passed. Physical-debug APK job `20260929T044047-c48de723468d`: exit 0, 72 Gradle tasks; the prior gate records its APK SHA-256. Device/topology limits remain as stated above.
