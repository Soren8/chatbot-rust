# Architecture & Roadmap

This document captures the current architecture of the project and the potential future roadmap.

## Current Architecture

- **Workspace layout** – The Cargo workspace lives at the repository root. It contains three crates: `chatbot-core` (business logic, config, providers, persistence), `chatbot-server` (Axum HTTP server and route handlers), and `chatbot-test-support` (shared fixtures for integration tests). Shared resources such as templates and static assets reside in `static/`, while persisted runtime data is stored under `data/`.
- **HTTP stack** – `chatbot-server` exposes all routes via Axum. Templates are rendered with Minijinja, CSP headers are enforced by middleware, and state-changing endpoints require per-session CSRF tokens managed by the Rust session store. CSRF protection is configurable via `.config.yml` (and the `CSRF` environment variable); disabling it also removes the `Secure` flag from session cookies to support non-HTTPS development environments.
- **Providers & chat flow** – The chat pipeline, provider abstractions, and TTS implementation are implemented in Rust and configured through `.config.yml`. Providers use async traits with streaming support and are exercised by cargo integration tests.
- **Sessions & storage** – Session state and chat history live in Rust-managed stores backed by on-disk encrypted files guarded through locks. Anonymous and authenticated flows share the same API surface.
- **Tooling & operations** – Development and CI rely on Docker. The `tests` service runs `cargo test` and supporting checks, while the runtime image builds the Axum binary. Build caches, Cargo registries, and generated logs are mounted under `temp/` per `AGENTS.md`.

## Roadmap

### Top Priority Improvements

- [x] **Rust Refactor:** All Flask routes, bridge helpers, and provider integrations have been ported to Rust.

- **UI/UX Improvements**
  - [ ] Lower friction for new chats by assigning a temporary title (e.g., "New Chat") that is automatically replaced with a contextual name based on chat content.
  - [x] Ability to delete chats from history.
  - [x] Ability to edit old chat entries.

- **Authentication & Security**
  - [ ] Outsource authentication to Keycloak or Authentik (or other OIDC-compliant systems).
  - [ ] Add proper email verification and CAPTCHA workflows to prepare for production.
  - An additional encryption password may be required for privacy requirements.

- **Security & Session Management**
  - [x] Avoid storing raw passwords in the session; use tokens or derive keys post-login.
  - [ ] Introduce a persistent session store (Redis/Postgres) for multi-instance deployments.
  - [x] Ensure password hashing uses a strong KDF with per-user salts.
  - [x] Provider metadata hygiene: the UI now receives only a sanitized model list (`provider_name`, `tier`), preventing accidental leakage of `api_key` or `base_url` values.
  - [x] Session isolation: anonymous users are assigned stable random guest IDs instead of the remote IP, eliminating cross-user memory leaks behind shared NAT gateways.
  - [x] Encryption key handling: login derives a Fernet key per user, stores it in-memory with an idle timeout, and never keeps the raw password. All persistence helpers accept the derived key instead of the plaintext password.
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
  - [ ] Require a non-default `SECRET_KEY` via environment; remove hardcoded fallbacks.
  - [x] Store all API keys and sensitive settings in environment variables only; avoid checking secrets into Git.
  - [ ] Validate `.config.yml` against a schema to catch missing or invalid fields.
  - [ ] Implement hybrid chat-history encryption:
        - [x] Derive a per-user data key from a user-supplied passphrase.
        - [x] Encrypt set names and metadata on disk to prevent leakage of conversation identifiers.
        - [ ] Allow optional registration of multiple hardware authenticators
     (Touch ID, YubiKey, WebAuthn) for seamless unlock on trusted devices with fallback to the passphrase on new or unregistered devices.

- **Rate Limiting & Concurrency**
  - [ ] Replace the bespoke rate limiter with a production-ready alternative and support per-user + global caps.
  - [ ] Hook background cleanup jobs to purge expired sessions and chats proactively.
  - [ ] Consider switching to Sled (or similar) for concurrent data storage while providing migrations for existing JSON data.
  - [ ] Enhance test concurrency across integration suites.

- **Error Handling & Logging**
  - [ ] Standardize on JSON error responses with proper HTTP status codes rather than plain text.
  - [ ] Narrow error scopes; only catch expected exceptions and add contextual logging before rethrowing.
  - [ ] Centralize logging configuration with structured output.

- **Code Quality & Style**
  - [ ] Enforce consistent formatting and lint rules via pre-commit.
  - [ ] Remove unused imports and dead code to reduce noise.

- **Privacy Tiers**
  1. **Standard**: Server-managed encryption with full account recovery.
  2. **Private**: Client-derived keys for zero-knowledge storage (on-prem LLMs only).
  3. **Ephemeral**: Memory-only sessions with no persistent data (free/on-prem LLMs).
  See [design-privacy.md](design-privacy.md) for details.

- **Docker & Deployment**
  - [x] Optimize the `Dockerfile` with a multi-stage build so that only artifacts ship in the final image.
  - [ ] Add a health-check endpoint so orchestrators can verify service readiness.
  - [ ] Provide sample deployment configurations (e.g., Docker Compose overrides, Kubernetes/Helm charts) for self-hosted and cloud environments.

- **LLM Provider Abstraction**
  - [ ] Consider adding an async provider interface for non-blocking streaming across all providers.
  - [ ] Document provider-specific fields (e.g., `template` usage, base URLs) and include example configs.
  - [ ] Break out LLM providers into a git submodule so they can be shared and consumed by other projects or front ends.
  - [ ] Establish semantic versioning and backward-compatibility guarantees for the provider interface.

- **Voice Mode**
  - [ ] Silero VAD voice activity detection.
  - [ ] Whisper Large v3 turbo.
  - [ ] Smart Turn v2 by @trydaily.
  - [x] Kokoro_tts.
  - [x] Fish Speech API support.

- **Documentation**
  - [ ] Host a `/docs` page or integrate with tooling like Redoc to expose interactive docs.
  - [ ] Consider publishing documentation to ReadTheDocs or GitHub Pages for auto-publishing from the repo.
