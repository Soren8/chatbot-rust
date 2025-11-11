# Rust Refactor Migration

## Guiding Principles
- Pair each migration milestone with tests that document existing Python behavior and verify the Rust replacement.
- Prioritize Rust-based test coverage; new scenarios should be exercised via cargo tests so they remain after Python teardown.
- Maintain functional parity during the transition; keep Python implementations available until their Rust counterparts are tested and ready.
- Ensure Rust additions interoperate cleanly with remaining Python modules; migrate one module at a time.
- Preserve provider contracts by validating configuration and integrations whenever the abstraction layer changes.
- Capture architecture and deployment updates as they happen so the team stays aligned.

## Checklist
- [x] Inventory current Python modules and their entry points
- [x] Define Rust project structure (crate layout, modules, build tooling)
- [x] Establish interop strategy during transition (Rust-hosted, embedded Python bridge)
- [x] Stand up Rust web server shell (Axum) with health check and placeholder UI route
- [x] Proxy Axum endpoints to existing Flask routes for interim functionality
    - [x] TTS endpoint `/tts'
- [x] Migrate Flask routes to Axum handlers that delegate to Python logic via the bridge, following the Route-by-Route Migration Loop
    - [x] Auth endpoints
        - [x] `/signup`
        - [x] `/login`
        - [x] `/logout`
    - [x] Base endpoints
        - [x] `/` (home)
        - [x] `/health`
        - [x] `/static`
    - [x] Chat endpoints
        - [x] `/chat`
        - [x] `/regenerate`
        - [x] `/reset_chat`
    - [x] TTS endpoint `/tts'
    - [x] Set management endpoints
        - [x] `/get_sets`
        - [x] `/create_set`
        - [x] `/delete_set`
        - [x] `/load_set`
- [x] System prompts and memory endpoints
        - [x] `/update_memory`
        - [x] `/update_system_prompt`
        - [x] `/delete_message`
- [x] Port configuration handling from `app/config.py` to Rust equivalent
    - Introduced `chatbot_core::config` for `.config.yml` loading, env substitution, and cached provider lookup with test reset helper.
- [x] Reimplement `app/chat_logic.py` core functionality in Rust
- [x] Recreate provider abstractions (`app/llm/`) as Rust traits and implementations
  - Providers status:
    - [x] OpenAI — Rust implementation with streaming & test-chunk support
    - [x] Ollama — Rust implementation with streaming fallback to test chunks and parity coverage
  - [x] Migrate data persistence layer (`data/`) to Rust using write locks
- [x] Align logging and error handling with Rust tooling
- [x] Update testing strategy (unit, integration, provider tests) for Rust codebase
  - Integration tests now detect Python tracebacks, server-side 5xx, and bridge errors
- [x] Document deployment changes, make note of `temp/` scratchpad usage, and update Docker setup
- [x] Fix slow tests
- [x] Port remaining proxied routes to native Rust handlers
    - [x] `/`
    - [x] `/signup`
    - [x] `/login`
    - [x] `/api/tts*`
- [x] Move chat preparation/finalization off the Python bridge
    - [x] `chat_prepare`
    - [x] `chat_finalize`
    - [x] `regenerate_prepare`
- [x] Reimplement TTS generation in Rust to eliminate `app/tts.py` dependency
- [x] Replace Python bridge session/CSRF handling with Rust implementation
- [x] Remove remaining Python components

With the bridge retired, the legacy Flask modules, pytest suite, and related Docker/Python tooling have been removed. Static asset hardening checks now live in Rust integration tests (`chatbot-server/tests/static_assets.rs`), and the GitHub workflow focuses on secret scanning while local/Compose-based jobs continue to run `cargo test` for coverage.

## Repository Layout Update
- The Cargo workspace now lives at the repository root (`Cargo.toml`, `Cargo.lock`, and the `chatbot-*` crates sit alongside `docs/` and `.github/scripts/`).
- HTML templates previously stored under `app/templates/` now live in `/static/templates/` and are embedded via `include_str!`.
- Static assets moved from `app/static/` to `/static/` (templates included under `/static/templates/`); Docker images expose them via `CHATBOT_STATIC_ROOT=/app/static`.
- The `app/` package and remaining Python bridge modules have been removed; tests and tooling operate solely through Rust.

### Route-by-Route Migration Loop
For each Flask endpoint (grouped where it makes sense):
1. **Baseline tests** – ensure pytest coverage and bridge parity tests exercise the current Python behaviour; add cases if gaps exist.
2. **Port handler** – implement the equivalent Axum handler (initially calling into Python via the bridge until the Rust logic is ready).
3. **Rust integration tests** – cover new behaviour (status codes, headers, cookies, CSRF) using tower/axum test helpers.
4. **Run suites** – execute `docker compose run --rm tests pytest …` and the relevant `cargo test` set; keep CI scripts green.
5. **Interactive check** – verify the route manually in the UI to confirm end-to-end behaviour.
6. **Iterate** – once parity is confirmed, refactor the underlying business logic (e.g., chat logic or providers) into Rust and repeat.

## Item 1: Python Inventory (2024-11-24)
**Application package**
- `app/__init__.py`: Flask app factory (`create_app`), config bootstrap, logging setup.
- `app/config.py`: Centralized configuration, reads `.config.yml`, defines provider settings and logging configuration.
- `app/chat_logic.py`: Core chat flow; orchestrates providers, history persistence, and prompts.
- `app/routes.py`: Flask routes for chat UI, authentication, static assets, provider endpoints.
- `app/user_manager.py`: User/session management helpers.
- `app/tts.py`: Text-to-speech helpers.
- `app/llm/base_provider.py`: Base class defining provider interface.
- `app/llm/openai_provider.py`: OpenAI provider implementation.
- `app/llm/ollama_provider.py`: Ollama provider implementation.

**Supporting scripts & entry points**
- `flask run` / `python -m flask --app app:create_app`: primary web entry point via Flask factory.
- `chat_logic_test.py`: ad-hoc script/executable entry to exercise chat logic in isolation.
- `provider-test.py`: CLI harness to invoke providers with prompts; accepts `--provider`.
- `tests/` package (`pytest` targets): regression coverage for security and static asset controls.

**Observations**
- `python -m app` currently lacks an `app/__main__.py`; future Rust-backed CLI should supply this if we keep the command documented.
- No dedicated background worker modules; everything flows through Flask synchronously.

## Item 2: Proposed Rust Project Structure
> The structure outlined below reflects the initial workspace layout during early migration; the current organization is described in **Repository Layout Update** above.
- `rust/` directory at repo root housing the new codebase alongside Python app.
- `rust/Cargo.toml`: workspace manifest with a primary crate named `chatbot_core` (lib) and optional binary `chatbot_server`.
- `rust/src/lib.rs`: library entry exposing bridge helpers and shared logic for both the Axum server and future Rust crates.
- Module layout under `rust/src/`:
  - `config/` (config loading + validation mirroring `app/config.py`).
  - `chat/` (business logic equivalent to `app/chat_logic.py`).
  - `providers/` (`mod.rs`, `openai.rs`, `ollama.rs`, trait definitions).
  - `routes/` (HTTP adapters if we ship a Rust web server, e.g., Axum).
  - `persistence/` (chat history, file I/O abstractions).
  - `bridge/` (interop helpers exposed to Python).
- `rust/src/bin/server.rs`: optional Axum-based executable once routing migrates.
- Tooling: rely on `cargo` for Rust builds/tests; add `maturin` later only if we need Python-packaged wheels. Keep `ruff`/`black` for Python during transition.
- Workspace planning: leave room for future crates (e.g., `providers-*` as separate crates) if we split functionality later.

## Item 3: Rust/Python Interop Strategy
- Use **PyO3** to embed the Python interpreter inside the Rust server so existing business logic remains callable while we migrate modules.
- Expose Rust functions/structs that mirror current Python interfaces, starting with pure functions for config + chat logic; maintain compatibility layers in Python packages that dispatch to Rust when available.
- Keep data models serialized via serde ↔ dataclasses to ensure predictable boundary formats; prefer JSON-serializable structs to decouple from Python object internals.
- Provide a `bridge` module so Rust can embed Python during the routing-first migration, handling GIL management and graceful fallbacks.
- Expose helper wrappers (e.g., `bridge::call_python_function`) to centrally manage imports and callable dispatch from Rust into Python.
- Run the Rust web server first (Axum) while calling into existing Python business logic; progressively replace those Python calls as modules migrate.
