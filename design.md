# Design

## Potential Improvements

### Top Priority Improvements

- **UI Improvements**
  - Lower friction for new chats with temporary then automatic naming.
  - Ability to delete chats from history.

- **Authentication & Security**
  - Outsource authentication to Keycloak or Authentik.
  - Add proper email verification and CAPTCHA workflows to prepare for production.


- **Project Structure & Packaging**
  - Add a proper Python package layout (e.g., `pyproject.toml` or `setup.py`) so consumers can install via pip.
  - Include a `.config.yml.example` at the repo root to illustrate required settings.
  - Provide a top-level `README.md` with quickstart instructions and project overview.

- **Dependency Management & CI**
  - Pin all dependencies (use exact versions in `requirements.txt` or switch to Poetry with a lock file).
  - Add a CI workflow (e.g., GitHub Actions) to run linters, type checks, and tests on each pull request.

- **Testing**
  - Convert ad-hoc scripts (`chat_logic_test.py`, `provider-test.py`) into proper `pytest` unit tests.
  - Measure test coverage and target critical modules: `user_manager`, `routes`, `chat_logic`, and each provider.
  - Spin up the Flask app in test mode for end-to-end route testing (signup/login, JSON APIs).

- **Configuration & Secrets**
  - Require a non-default `SECRET_KEY` via environment; remove hardcoded fallbacks.
  - Store all API keys and sensitive settings in environment variables only; avoid checking secrets into Git.
  - Validate `.config.yml` against a schema (using Pydantic or Cerberus) to catch missing or invalid fields early.

- **Security & Session Management**
  - Avoid storing raw passwords in the session; use tokens or derive keys post-login.
  - Move from custom in-memory session storage to Flask’s session (backed by Redis or a database in production).
  - Ensure password hashing uses a strong KDF (bcrypt or Argon2) with per-user salts.

- **Rate Limiting & Concurrency**
  - Replace custom IP-based rate limiter with a battle-tested extension like `Flask-Limiter`.
  - Hook `clean_old_sessions()` into a regular cleanup job or request hook to avoid stale session buildup.

- **Error Handling & Logging**
  - Standardize on JSON error responses with proper HTTP status codes rather than plain text.
  - Narrow except-block scopes; only catch expected exceptions and add contextual logging before re-raising.
  - Centralize logging configuration (use `Config.configure_logging()` once at startup).

- **Code Quality & Style**
  - Add type hints across public interfaces (e.g., `chat_logic.py`, provider APIs, `user_manager.py`).
  - Enforce consistent formatting and lint rules via pre-commit (Black, Flake8, isort).
  - Remove unused imports and dead code to reduce noise.

- **Data Storage**
  - For production, migrate from JSON files to a lightweight database (SQLite or other) to handle concurrency and queries.
  - If file storage remains, add file-level locking around reads/writes to prevent data corruption.

- **Docker & Deployment**
  - Optimize the `Dockerfile` with a multi-stage build: install dependencies separately and ship only artifacts in the final image.
  - Add a health-check endpoint so orchestrators can verify service readiness.

- **LLM Provider Abstraction**
  - Consider adding an async provider interface for non-blocking streaming.
  - Document provider-specific fields (e.g., `template` usage, base URLs) and include example configs.

- **Documentation**
  - Create an OpenAPI/Swagger spec or at least a Markdown API reference for all HTTP routes.`
  - Host a `/docs` page or integrate with tools like Redoc to expose interactive API docs.