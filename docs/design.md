# Architecture & Roadmap

This document captures the current architecture of the project and the potential future roadmap.

## Current Architecture

- **Workspace layout** – The Cargo workspace lives at the repository root. It contains three crates: `chatbot-core` (business logic, config, history, persistence, sessions), `chatbot-server` (Axum HTTP server, route handlers, and LLM/TTS provider adapters under `chatbot-server/src/providers/`), and `chatbot-test-support` (shared fixtures for integration tests). Shared resources such as templates and static assets reside in `static/`, while persisted runtime data is stored under `data/`.
- **HTTP stack** – `chatbot-server` exposes all routes via Axum, including `GET /health` for liveness. Templates are rendered with Minijinja, CSP headers are enforced by middleware, and state-changing endpoints require per-session CSRF tokens managed by the Rust session store. CSRF protection is configurable via `.config.yml` (and the `CSRF` environment variable); disabling it also removes the `Secure` flag from session cookies to support non-HTTPS development environments.
- **Providers & chat flow** – The chat pipeline is orchestrated in Rust and configured through `.config.yml`. Provider implementations (OpenAI-compatible, XAI) live in `chatbot-server` and use async traits with streaming support, exercised by cargo integration tests.
- **Brave Search integration** – Non-XAI providers (OpenAI-compatible API) support web search via the Brave Search REST API. When `web_search=true` is requested, the server performs a two-phase call: first a non-streaming call with an OpenAI function-calling tool definition to let the model decide whether to search and craft the query, then (if a `brave_web_search` tool call is returned) the query is executed directly against the Brave Search API via `reqwest`, and the results are injected as a tool message before the final streaming response. XAI models retain their native search capability unchanged. Configured via the `BRAVE_API_KEY` environment variable.
- **Sessions & storage** – Session state lives in a Rust-managed in-memory store (guest RAM mirror only). Chat history for authenticated users is stored in an embedded **redb** database of AEAD ciphertext blobs via `HistoryService`, with an optional multi-set ciphertext cache keyed `(user_id, set_id)` (see [design-history-store.md](design-history-store.md)). Pre-redb `user_sets/{user}/sets.json` is **migration-only** and lives permanently in `chatbot-core::legacy_sets_json` (lazy import into redb, then `sets.json.migrated.bak`). Anonymous flows remain ephemeral/RAM-only.
- **Tooling & operations** – Development and CI rely on Docker. The `tests` service runs `cargo test` and supporting checks, while the runtime image builds the Axum binary. Build caches, Cargo registries, and generated logs are mounted under `temp/` per `AGENTS.md`.

## Roadmap

### Top Priority Improvements

- [x] **Rust Refactor:** All Flask routes, bridge helpers, and provider integrations have been ported to Rust.

- **UI/UX Improvements**
  - [ ] Lower friction for new chats by assigning a temporary title (e.g., "New Chat") that is automatically replaced with a contextual name based on chat content.
  - [x] Ability to delete chats from history (`/delete_message` requires `pair_index` + matching `user_message` at that index; content mismatch → 409. `ai_message` may be sent by the client but is not used for the server-side match).
  - [x] Ability to edit old chat entries.

- **Authentication & Security**
  - [ ] Outsource authentication to Keycloak or Authentik (or other OIDC-compliant systems).
  - [ ] Add proper email verification and CAPTCHA workflows to prepare for production.
  - An additional encryption password may be required for privacy requirements.

- **Security & Session Management**
  - [x] Avoid storing raw passwords in the session; use tokens or derive keys post-login.
  - [x] Ensure password hashing uses a strong KDF with per-user salts.
  - [x] Provider metadata hygiene: the UI now receives only a sanitized model list (`provider_name`, `tier`), preventing accidental leakage of `api_key` or `base_url` values.
  - [x] Session isolation: anonymous users are assigned stable random guest IDs instead of the remote IP, eliminating cross-user memory leaks behind shared NAT gateways.
  - [x] Encryption key handling: login derives a Fernet key per user; the server stores only an HMAC key verifier (not the key itself). Clients send the key per request via `X-Enc-Key`, wrap it locally (IndexedDB / WebAuthn PRF / native keystore), and the server zeroizes it after each request. Browser use requires a secure context (https or localhost); see README for Tailscale Serve dev setup and [design-privacy.md](design-privacy.md#per-request-encryption-key-model).
  - [x] CSRF protection – every state-changing route validates a per-session token; the token is exposed to forms and Fetch calls, and the client attaches it automatically.
  - [x] Frontend sanitisation: set names rendered in the chat UI are escaped before insertion, closing stored-XSS vectors through crafted identifiers.
  - [x] CSP refinements: media sources now explicitly allow the `blob:` scheme used for streamed TTS playback while the rest of the policy remains locked down.

- **Project Structure & Packaging**
  - [x] Adopt a standardized Cargo workspace layout for packaging, publishing, and dependency management.
  - [x] Include a `.config.yml.example` at the repo root to illustrate required settings.
  - [x] Provide a top-level `README.md` with quickstart instructions and project overview.

- **Dependency Management & CI**
  - [ ] Switch to pinned dependencies.
  - [ ] Enable automated dependency updates for security updates.
  - [x] Add a CI workflow to run tests and secret scans on each pull request.

- **Testing**
  - [x] Convert ad-hoc scripts into proper tests or retire them.
  - [ ] Measure test coverage and target critical modules (session manager, providers, chat flow) with explicit coverage goals.
  - [x] Spin up the app in test mode for end-to-end route testing (signup/login, JSON APIs).
  - [x] Establish mocking and external-service stubbing best practices for LLM providers and authentication flows.

### Lower Priority Improvements

- **Configuration & Secrets**
  - [x] Require a non-default `SECRET_KEY` via environment; remove hardcoded fallbacks.
  - [x] Store all API keys and sensitive settings in environment variables only — Compose/`.config.yml` use `${VAR}` substitution; boot refuses plaintext provider `api_key` values and `vars:`-backed key refs.
  - [x] Validate `.config.yml` against a schema to catch missing or invalid fields.
  - [x] Protect `.env` and `.config.yml` from AI agent access via the **agent devcontainer** (secret overlays + sandbox). Run cloud-connected agents only in that environment — see [`.devcontainer/README.md`](../.devcontainer/README.md). Do not run agents on the host against the live workspace.
  - [x] Dependabot (`.github/dependabot.yml`): weekly PRs for Cargo, GitHub Actions, and Docker base images — **review/merge only**, no automerge. Direct crate deps pinned to current `Cargo.lock` versions.
  - [ ] Implement hybrid chat-history encryption:
        - [x] Derive a per-user data key from a user-supplied passphrase.
        - [x] Encrypt set names and metadata on disk to prevent leakage of conversation identifiers.
        - [x] Per-request key transport: clients send `X-Enc-Key` on every authenticated data call; server validates against HMAC verifier and keeps ciphertext-only in-memory cache.
        - [x] Tiered client key wrapping for **shipped platforms**: IndexedDB non-extractable key (web default), WebAuthn PRF opt-in, Android Keystore on Capacitor. (iOS still open below.)
        - [ ] iOS Keychain plugin mirroring `NativeSecureKey` when the iOS Capacitor target is added.
        - [ ] Allow optional registration of multiple hardware authenticators
     (Touch ID, YubiKey, WebAuthn) for seamless unlock on trusted devices with fallback to the passphrase on new or unregistered devices.

- **Rate Limiting & Concurrency**
  - [x] Add a production-ready rate limiter with per-user + global caps (in-process sliding 60s window; generate-lock unchanged). Config: `rate_limit_*_per_minute` / `RATE_LIMIT_*` (`0` disables).
  - [x] Hook background cleanup jobs to purge expired sessions and chats proactively (`session::purge_expired_sessions` + `SESSION_PURGE_INTERVAL_SECS` background task).
  - [x] Durable chat history on **redb** via `HistoryService` (AEAD+AAD, CAS, PrepareCapture, multi-set `SetCache`, permanent `legacy_sets_json` migration, client `set_id`/`expected_version` + 409 reload UX). See [design-history-store.md](design-history-store.md). Operator: delete `sets.json.migrated.bak` only after a stable redb release.
  - [ ] Enhance test concurrency across integration suites.

- **Error Handling & Logging**
  - [x] Standardize on JSON error responses with proper HTTP status codes rather than plain text (`http_error::HttpError` / `api_error` across `chatbot-server` routes; integration test `http_errors.rs`).
  - [x] Narrow error scopes; only catch expected exceptions and add contextual logging before rethrowing (`http_error` typed mappers: `map_session_err`, `map_user_store_err`, `map_history_err`, etc.).
  - [x] Centralize logging configuration with structured output (`chatbot_core::logging::init_logging`; `LOG_FORMAT=json|plain`, `LOG_ANSI`, `RUST_LOG`/`LOG_LEVEL`).

- **Code Quality & Style**
  - [ ] Enforce consistent formatting and lint rules via pre-commit.
  - [ ] Remove unused imports and dead code to reduce noise.

- **Privacy Modes**
  1. **Recoverable Mode**: Server-managed encryption with full account recovery.
  2. **Private Mode**: Client-derived keys for zero-knowledge storage.
  3. **Ephemeral Mode**: Memory-only sessions with no persistent data.
  See [design-privacy.md](design-privacy.md) for details.

- **Docker & Deployment**
  - [x] Optimize the `Dockerfile` with a multi-stage build so that only artifacts ship in the final image.
  - [x] Health checks for orchestrators — `GET /health` liveness JSON; Compose `healthcheck` on **webserver** (curl, honours `CHATBOT_BIND_ADDR` port); optional deep readiness via `GET /health?deep=true` (redb + voice-service probes, 503 when degraded).
  - [x] Provide sample deployment configurations (e.g., Docker Compose overrides, Kubernetes/Helm charts) for self-hosted and cloud environments (`deploy/compose/`, `deploy/helm/chatbot/`).

- **LLM Provider Abstraction**
  - [x] Async provider interface with streaming (OpenAI-compatible + XAI adapters in `chatbot-server/src/providers/`).
  - [ ] Document provider-specific fields (e.g., base URLs) and include example configs.
  - [ ] Break out LLM providers into a git submodule so they can be shared and consumed by other projects or front ends.
  - [ ] Establish semantic versioning and backward-compatibility guarantees for the provider interface.

- **Mobile Frontends**
  - [x] Capacitor Android shell — wrap existing web UI in native Android app (server-pull WebView)
  - [x] Native microphone plugin — bypass browser audio restrictions on mobile
  - [ ] Android Auto integration — **partial**: `CarAppService` / `VoiceScreen` implemented and usable on DHU/emulator; still open for production: replace `HostValidator.ALLOW_ALL_HOSTS_VALIDATOR`, Play-trusted install for real head units, production host allowlist. See [mobile-apps.md](mobile-apps.md).
  - [ ] iOS support via Capacitor (same codebase, low priority)
  - See [mobile-apps.md](mobile-apps.md) for full plan and AA distribution constraints.

- **Voice Mode** — Default TTS provider is `kokoro`; select Qwen3-TTS with `tts_provider: "qwen"` in `.config.yml`.
  - [x] Silero VAD voice activity detection on **desktop/browser** (`static/deps/vad/`, `chat.js`).
  - [x] Native mobile VAD — RMS-based `NativeMicUtteranceVAD` on Capacitor (no Silero in WebView); Android Auto `VoiceScreen` also uses RMS. See [mobile-apps.md](mobile-apps.md).
  - [ ] Whisper Large v3 turbo.
  - [ ] Smart Turn v2 by @trydaily.
  - [x] Kokoro TTS — vertically integrated into `chatbot-cuda` voice-service; select with `tts_provider: "kokoro"` in `.config.yml`. Supports per-sentence streaming (`/v1/tts/kokoro/stream`) using a thread→asyncio-queue bridge for true low-latency first audio. Default voice `af_heart`; configurable via `tts_voice`.
  - [ ] Fish Speech S2 — natively supports low TTFA streaming; evaluate for production use (code path exists; not production default).
  - [ ] Qwen3-TTS — **partial**: vertically integrated into `chatbot-cuda` (`tts_provider: "qwen"`, CustomVoice model, `tts_voice` default "Ryan"). Not complete as a low-TTFA streaming peer to Kokoro: official package synthesizes the full waveform before return (no streaming API); community streaming forks need audit, or treat Fish Speech S2 as the streaming alternative.
  - [x] Parakeet STT — NVIDIA Parakeet TDT 0.6B v2 for speech-to-text, vertically integrated into `chatbot-cuda` voice-service.

- **Documentation**
  - [ ] Host a `/docs` page or integrate with tooling like Redoc to expose interactive docs.
  - [ ] Consider publishing documentation to ReadTheDocs or GitHub Pages for auto-publishing from the repo.
