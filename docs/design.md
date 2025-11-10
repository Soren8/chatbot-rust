# Architecture & Roadmap

This document outlines the high-level architecture and planned enhancements for the project, including both critical and lower-priority tasks. Use this roadmap to guide development efforts, ensure code quality, and maintain consistency across features.

## Roadmap

### Top Priority Improvements

- [ ] **Rust Refactor:** For the ongoing Python-to-Rust refactor, review `rust-refactor.md` for guiding principles and the latest checklist before making related changes.

- **UI/UX Improvements**
  - [ ] Lower friction for new chats by assigning a temporary title (e.g., "New Chat") that is automatically replaced with a contextual name based on chat content.
  - [x] Ability to delete chats from history.

- **Authentication & Security**
  - [ ] Outsource authentication to Keycloak or Authentik (or other OIDC-compliant systems).
  - [ ] Add proper email verification and CAPTCHA workflows to prepare for production.
  - An additional encryption password may be required for privacy requirements.

- **Security & Session Management**
  - [x] Avoid storing raw passwords in the session; use tokens or derive keys post-login.
  - [ ] Use Flask-Login and Flask-Session (backed by Redis or a database in production) instead of custom in-memory storage.
  - [x] Ensure password hashing uses a strong KDF with per-user salts.
  - [x] Provider metadata hygiene: the UI now receives only a sanitized model list (`provider_name`, `tier`), preventing accidental leakage of `api_key` or `base_url` values.
  - [x] Session isolation: anonymous users are assigned stable random guest IDs instead of the remote IP, eliminating cross-user memory leaks behind shared NAT gateways.
  - [x] Encryption key handling: login derives a Fernet key per user, stores it in-memory with an idle timeout, and never keeps the raw password. All persistence helpers accept the derived key instead of the plaintext password.
  - [x] CSRF protection – every state-changing route validates a per-session token; the token is exposed to forms and Fetch calls, and the client attaches it automatically.
  - [x] Frontend sanitisation: set names rendered in the chat UI are escaped before insertion, closing stored-XSS vectors through crafted identifiers.
  - [x] CSP refinements: media sources now explicitly allow the `blob:` scheme used for streamed TTS playback while the rest of the policy remains locked down.

- **Project Structure & Packaging**
  - [x] Adopt a standardized `cargo.toml` layout for packaging, publishing, and dependency management.
  - [x] Include a `.config.yml.example` at the repo root to illustrate required settings.
  - [ ] Provide a top-level `README.md` with quickstart instructions and project overview.

- **Dependency Management & CI**
  - [ ] Switch to pinned dependencies
  - [ ] Enable automated dependency updates for security updates
  - [ ] Add a CI workflow (e.g., GitHub Actions) to run linters, type checks, and tests on each pull request.

- **Testing**
  - [ ] Convert ad-hoc scripts (`chat_logic_test.py`, `provider-test.py`) into proper tests.
  - [ ] Measure test coverage and target critical modules: `user_manager`, `routes`, `chat_logic`, and each provider.
  - [x] Spin up the app in test mode for end-to-end route testing (signup/login, JSON APIs).
  - [x] Establish mocking and external-service stubbing best practices for LLM providers and authentication flows.

### Lower Priority Improvements

- **Configuration & Secrets**
  - [ ] Require a non-default `SECRET_KEY` via environment; remove hardcoded fallbacks.
  - [x] Store all API keys and sensitive settings in environment variables only; avoid checking secrets into Git.
  - [ ] Validate .config file against a schema to catch missing or invalid fields.
  - [ ] Implement hybrid chat-history encryption:
    - [x] Derive a per-user data key from a user-supplied passphrase.
    - [ ] Allow optional registration of multiple hardware authenticators (Touch ID, YubiKey, WebAuthn) for seamless unlock on trusted devices with fallback to the passphrase on new or unregistered devices.

- **Rate Limiting & Concurrency**
  - [ ] Replace custom IP-based rate limiter with a battle-tested extension like (support per-user and global rate caps).
  - [ ] Hook `clean_old_sessions()` into a regular cleanup job or request hook to avoid stale session buildup.

- **Error Handling & Logging**
  - [ ] Standardize on JSON error responses with proper HTTP status codes rather than plain text.
  - [ ] Narrow except-block scopes; only catch expected exceptions and add contextual logging before re-raising.
  - [ ] Centralize logging configuration (use `Config.configure_logging()` once at startup) and consider a structured logging library (e.g., structlog or JSONFormatter).

- **Code Quality & Style**
  - [ ] Enforce consistent formatting and lint rules via pre-commit.
  - [ ] Remove unused imports and dead code to reduce noise.

- **Privacy Tiers**
  1. **Standard**: Server-managed encryption with full account recovery
  2. **Private**: Client-derived keys for zero-knowledge storage (on-prem LLMs only)
  3. **Ephemeral**: Memory-only sessions with no persistent data (free/on-prem LLMs)
  See [design-privacy.md](design-privacy.md) for details.

- **Docker & Deployment**
  - [ ] Optimize the `Dockerfile` with a multi-stage build: install dependencies separately and ship only artifacts in the final image.
  - [ ] Add a health-check endpoint so orchestrators can verify service readiness.
  - [ ] Provide sample deployment configurations (e.g., Docker Compose, Kubernetes/Helm charts) for self-hosted and cloud environments.

- **LLM Provider Abstraction**
  - [ ] Consider adding an async provider interface for non-blocking streaming.
  - [ ] Document provider-specific fields (e.g., `template` usage, base URLs) and include example configs.
  - [ ] Break out LLM providers into a git submodule so they can be shared and consumed by other projects or front ends.
  - [ ] Establish semantic versioning and backward-compatibility guarantees for the provider interface.

- **Voice Mode**
  - [ ] Silero VAD voice activity detection
  - [ ] Whisper Large v3 turbo
  - [ ] Smart Turn v2 by @trydaily
  - [x] Kokoro_tts

- **Documentation**
  - [ ] Host a `/docs` page or integrate with tools like Redoc to expose interactive docs.
  - [ ] Consider publishing documentation to ReadTheDocs or GitHub Pages for auto-publishing from the repo.
