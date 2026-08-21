# AGENTS.md - Development Guide

Project-specific agent instructions for chatbot-rust.

## Running tests

Always the compose `tests` service — full workspace suite, including live integration tests against the test app. Do not run `cargo test` on the host or agent toolchain.

```bash
./scripts/run-tests.sh
```

First-party `static/*.js` is parsed by the `js_syntax` cargo test (`oxc_parser`, locked in `Cargo.lock`). Do not install Node/npm for this, and do not add hand-rolled brace scanners.

Logs: `temp/test-logs/`. Caches: `temp/.cargo/`, `temp/.docker/tests/`.

## Build & Run Commands

- Tests: `./scripts/run-tests.sh` (compose `tests` service, full suite)
- Do not run `cargo test` / app binaries outside that container
- Allowed compose from the sandbox: **`tests` only**. It injects its own env and does not need workspace `.env`.
- Do **not** `docker compose up`, `build`, or recreate **`webserver`** or **`voice-service`**. Ask the **user** to rebuild/restart those on the host when a live deploy is needed.

`static/` and templates are **copied into the image at build time** (hermetic Docker). UI/asset changes do not show on a running phone or browser until the user rebuilds/restarts **webserver on the host**. Agents should note that in the handoff, not run compose themselves.

## Code Style Guidelines

- **Imports**: Standard library first, then third-party, then local modules
- **Error Handling**: Use `anyhow` or `thiserror` for error handling, log errors appropriately with `tracing`
- Use logging (via `tracing`) instead of print statements for debugging

## Scratchpad / Temp Files

- Use `temp/` for ephemeral notes (e.g., TODOs) — it is gitignored
- Never reference `temp/` items in commit messages
- Keep `temp/todo.md` updated as you progress
- Preserve the `temp/.cargo/` cache directory; do not delete it because it stores Rust build artifacts used by other agents. If it is missing, recreate it inside `temp/` (never at repo root).
- Keep Docker build caches under `temp/.docker/`; create that directory inside `temp/` when needed so the repository root stays free of sandbox artefacts.
- Store test run artifacts under `temp/test-logs/`; do not create a top-level `test-logs/` directory.

## Important Notes

- Before starting work, read `docs/design.md` and `docs/design-privacy.md` to align with the current architecture and privacy posture.
- Always validate provider configurations before committing
- NEVER add cache busting mechanisms (e.g., query parameters on script tags) unless the user explicitly asks for it. Assume the user knows how to clear their cache.
- When searching, skip gitignored trees (`data/`, `temp/`, `target/`, `.git/`) — they are large and noisy.
- Do not read `.env`, `.config.yml`, or `data/` unless the user explicitly asks you to; in the sandbox these paths are stubs or examples only.
- The `/tts` endpoint uses a two-step "Pre-sign" pattern for browser compatibility: a `POST` to `/tts` submits text and receives a token, followed by a `GET /tts_stream/{token}` for native browser streaming. `POST /tts` requires CSRF and respects `tts_access` (`anyone` | `authenticated` | `premium`; default `anyone`). Do not reintroduce unauthenticated webserver `/api/tts*` routes; the voice-service TTS HTTP API is internal (webserver → GPU), not a public product API.
