# Architecture & Roadmap

This document outlines the high-level architecture and planned enhancements for the project, including both critical and lower-priority tasks. Use this roadmap to guide development efforts, ensure code quality, and maintain consistency across features.

## Roadmap

### Top Priority Improvements

- **UI/UX Improvements**
  - Lower friction for new chats by assigning a temporary title (e.g., "New Chat") that is automatically replaced with a contextual name based on chat content.
  - Ability to delete chats from history.

- **Authentication & Security**
  - Outsource authentication to Keycloak or Authentik (or other OIDC-compliant systems).
  - Add proper email verification and CAPTCHA workflows to prepare for production.


- **Project Structure & Packaging**
  - Adopt Poetry with a standardized `pyproject.toml` layout for packaging, publishing, and dependency management.
  - Include a `.config.yml.example` at the repo root to illustrate required settings.
  - Provide a top-level `README.md` with quickstart instructions and project overview.
  - Refactor `routes.py` into domain-specific Flask Blueprints (e.g., auth, chat, sets, tts) under `app/<domain>/routes.py` and introduce an application factory (`create_app()`) to register them. This separates HTTP routing from core business logic in `services/` and keeps each module focused and maintainable.

- **Dependency Management & CI**
  - Switch to Poetry with a lock file to pin dependencies, and enable automated dependency updates (e.g., Dependabot or Renovate).
  - Add a CI workflow (e.g., GitHub Actions) to run linters, type checks, and tests on each pull request.

- **Testing**
  - Convert ad-hoc scripts (`chat_logic_test.py`, `provider-test.py`) into proper `pytest` unit tests.
  - Measure test coverage and target critical modules: `user_manager`, `routes`, `chat_logic`, and each provider.
  - Spin up the Flask app in test mode for end-to-end route testing (signup/login, JSON APIs).
  - Establish mocking and external-service stubbing best practices for LLM providers and authentication flows.

### Lower Priority Improvements

- **Configuration & Secrets**
  - Require a non-default `SECRET_KEY` via environment; remove hardcoded fallbacks.
  - Store all API keys and sensitive settings in environment variables only; avoid checking secrets into Git.
  - Validate `.config.yml` against a schema (using Pydantic or Cerberus) to catch missing or invalid fields early.
  - Implement hybrid chat-history encryption:
    - Derive a per-user data key from a user-supplied passphrase.
    - Allow optional registration of multiple hardware authenticators (Touch ID, YubiKey, WebAuthn) for seamless unlock on trusted devices with fallback to the passphrase on new or unregistered devices.

- **Security & Session Management**
  - Avoid storing raw passwords in the session; use tokens or derive keys post-login.
  - Use Flask-Login and Flask-Session (backed by Redis or a database in production) instead of custom in-memory storage.
  - Ensure password hashing uses a strong KDF (bcrypt or Argon2) with per-user salts.

- **Rate Limiting & Concurrency**
  - Replace custom IP-based rate limiter with a battle-tested extension like `Flask-Limiter` (support per-user and global rate caps).
  - Hook `clean_old_sessions()` into a regular cleanup job or request hook to avoid stale session buildup.

- **Error Handling & Logging**
  - Standardize on JSON error responses with proper HTTP status codes rather than plain text.
  - Narrow except-block scopes; only catch expected exceptions and add contextual logging before re-raising.
  - Centralize logging configuration (use `Config.configure_logging()` once at startup) and consider a structured logging library (e.g., structlog or JSONFormatter).

- **Code Quality & Style**
  - Add type hints across public interfaces (e.g., `chat_logic.py`, provider APIs, `user_manager.py`) and integrate MyPy for static type checking.
  - Enforce consistent formatting and lint rules via pre-commit (Black, Flake8, isort).
  - Remove unused imports and dead code to reduce noise.

- **Privacy Tiers**
  1. **Standard**: Server-managed encryption with full account recovery
  2. **Private**: Client-derived keys for zero-knowledge storage (on-prem LLMs only)
  3. **Ephemeral**: Memory-only sessions with no persistent data (free/on-prem LLMs)
  See [design-privacy.md](design-privacy.md) for details.

- **Docker & Deployment**
  - Optimize the `Dockerfile` with a multi-stage build: install dependencies separately and ship only artifacts in the final image.
  - Add a health-check endpoint so orchestrators can verify service readiness.
  - Provide sample deployment configurations (e.g., Docker Compose, Kubernetes/Helm charts) for self-hosted and cloud environments.

- **LLM Provider Abstraction**
  - Consider adding an async provider interface for non-blocking streaming.
  - Document provider-specific fields (e.g., `template` usage, base URLs) and include example configs.
  - Break out LLM providers into a git submodule so they can be shared and consumed by other projects or front ends.
  - Establish semantic versioning and backward-compatibility guarantees for the provider interface.

- **Documentation**
  - Create an OpenAPI/Swagger spec or at least a Markdown API reference for all HTTP routes.
  - Host a `/docs` page or integrate with tools like Redoc to expose interactive API docs.
  - Consider publishing documentation to ReadTheDocs or GitHub Pages for auto-publishing from the repo.
