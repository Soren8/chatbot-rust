# Rust Migration Checklist

## Guiding Principles
- Pair each migration milestone with tests that document existing Python behavior and verify the Rust replacement.
- Maintain functional parity during the transition; keep Python implementations available until their Rust counterparts are tested and ready.
- Ensure Rust additions interoperate cleanly with remaining Python modules; migrate one module at a time.
- Preserve provider contracts by validating configuration and integrations whenever the abstraction layer changes.
- Capture architecture and deployment updates as they happen so the team stays aligned.

## Checklist
- [x] Inventory current Python modules and their entry points
- [x] Define Rust project structure (crate layout, modules, build tooling)
- [x] Establish interop strategy during transition (FFI or HTTP bridge)
- [ ] Port configuration handling from `app/config.py` to Rust equivalent
- [ ] Reimplement `app/chat_logic.py` core functionality in Rust
- [ ] Recreate provider abstractions (`app/llm/`) as Rust traits and implementations
- [ ] Replace Flask routing with Rust web framework or adaptor
- [ ] Migrate data persistence layer (`data/`) to Rust-compatible solution
- [ ] Align logging and error handling with Rust tooling
- [ ] Update testing strategy (unit, integration, provider tests) for Rust codebase
- [ ] Document deployment changes, make note of `temp/` scratchpad usage, and update Docker setup
- [ ] Plan deprecation timeline for remaining Python components

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
- `rust/` directory at repo root housing the new codebase alongside Python app.
- `rust/Cargo.toml`: workspace manifest with a primary crate named `chatbot_core` (lib) and optional binary `chatbot_server`.
- `rust/src/lib.rs`: library entry exporting modules callable from Python (via FFI/PyO3) and by internal Rust binaries.
- Module layout under `rust/src/`:
  - `config/` (config loading + validation mirroring `app/config.py`).
  - `chat/` (business logic equivalent to `app/chat_logic.py`).
  - `providers/` (`mod.rs`, `openai.rs`, `ollama.rs`, trait definitions).
  - `routes/` (HTTP adapters if we ship a Rust web server, e.g., Axum).
  - `persistence/` (chat history, file I/O abstractions).
  - `bridge/` (interop helpers exposed to Python).
- `rust/src/bin/server.rs`: optional Axum-based executable once routing migrates.
- Tooling: use `maturin` for building Python wheels in development, `cargo test` for Rust unit/integration tests, `ruff`/`black` remain for Python during transition.
- Workspace planning: leave room for future crates (e.g., `providers-*` as separate crates) if we split functionality later.

## Item 3: Rust/Python Interop Strategy
- Adopt **PyO3 + maturin** to compile Rust modules into Python extension packages (`chatbot_core`), letting existing Python code import Rust replacements incrementally.
- Expose Rust functions/structs that mirror current Python interfaces, starting with pure functions for config + chat logic; maintain compatibility layers in Python packages that dispatch to Rust when available.
- Use feature flags and environment switches to toggle between Python and Rust implementations during rollout; default to Python until parity tests pass.
- Keep data models serialized via serde ↔ dataclasses to ensure predictable boundary formats; prefer JSON-serializable structs to decouple from Python object internals.
- Provide a `bridge` module so Rust can embed Python during the routing-first migration, handling GIL management and graceful fallbacks.
- Run the Rust web server first (Rocket or Axum) while calling into existing Python business logic; progressively replace those Python calls as modules migrate.

Next actions: scaffold the Rust web server, implement the Python bridge for route handlers, and backfill tests ensuring parity with current Flask endpoints.
