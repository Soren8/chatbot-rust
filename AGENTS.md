# AGENTS.md - Development Guide

Project-specific agent instructions for chatbot-rust.

## Running tests

Always the compose `tests` service. Do not run `cargo test` on the host or agent toolchain.

```bash
docker compose run --rm tests
```

The `tests` service caps CPU pressure at half the physical cores (`CARGO_BUILD_JOBS` / `RUST_TEST_THREADS`, min 1; SMT threads excluded) plus a hard `cpus` quota in cores' worth of CPU time (default 3, `TEST_CPUS` override) that also bounds single-rustc LLVM threads; adjust there if needed, not per-invocation.

If that run reports **any** failure — including tests that look unrelated to the current change — **stop and ask the user what to do**. Do not ignore them, skip them, filter cargo to a subset, treat them as pre-existing noise, commit, or declare the task done. Wait for an explicit instruction (fix now, bisect, continue anyway, etc.).

First-party `static/*.js` is parsed by the `js_syntax` cargo test (`oxc_parser`, locked in `Cargo.lock`). Do not install Node/npm for this, and do not add hand-rolled brace scanners.

Logs: `temp/test-logs/`. Caches: `temp/.cargo/`, `temp/.docker/tests/`.

## Build & Run Commands

- Tests: `docker compose run --rm tests` (full suite; **any** failure → stop and ask, including “unrelated”)
- Do not run `cargo test` / app binaries outside that container
- Allowed compose from the sandbox: **`tests` only**. It injects its own env and does not need workspace `.env`.
- Do **not** `docker compose up`, `build`, or recreate **`webserver`** or **`voice-service`**. Ask the **user** to rebuild/restart those on the host when a live deploy is needed.

`static/` and templates are **copied into the image at build time** (hermetic Docker). UI/asset changes do not show on a running phone or browser until the user rebuilds/restarts **webserver on the host**. Agents should note that in the handoff, not run compose themselves.

## CI/CD

- `.github/workflows/docker-build-push.yml` runs the same compose test suite, then builds and publishes the image only if tests pass (`needs: tests`). An image existing on Docker Hub implies a green commit.
- `.config-version` (repo root) is the minimum config schema version the app requires; the image carries it as the `chat.config_version` label, and the deploy side (iac) gates image deploys on it. Bump it in any PR that makes the app need new config keys. See `iac/docs/cicd.md`.
- Config parsing tolerates unknown keys at runtime (forward-compatible config deploys); typo protection lives in the `config_example_has_no_unknown_keys` test, which fails on unknown keys in `.config.yml.example`.

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

- **IMPORTANT:** Desktop and mobile (Capacitor) must work as similarly as possible. Diverge only when a Capacitor/WebView/OS limitation makes the shared path impossible. Do not invent a second architecture, playback pipeline, or API shape for native.
- Before starting work, read `docs/design.md` and `docs/design-privacy.md` to align with the current architecture and privacy posture.
- Always validate provider configurations before committing
- Never add cache busting mechanisms (e.g., query parameters on script tags) unless the user explicitly asks for it. Assume the user knows how to clear their cache.
- When searching, skip gitignored trees (`data/`, `temp/`, `target/`, `.git/`) — they are large and noisy.
- Do not read `.env`, `.config.yml`, or `data/` unless the user explicitly asks you to; in the sandbox these paths are stubs or examples only.
- The `/tts` endpoint uses a two-step "Pre-sign" pattern for browser compatibility: a `POST` to `/tts` submits text and receives a token, followed by a `GET /tts_stream/{token}` for native browser streaming. `POST /tts` requires CSRF and respects `tts_access` (`anyone` | `authenticated` | `premium`; default `anyone`). Do not reintroduce unauthenticated webserver `/api/tts*` routes; the voice-service TTS HTTP API is internal (webserver → GPU), not a public product API.
- Native voice-mode barge-in is two-phase: record at speech-like start, stop TTS only after `REAL_SPEECH_MS` of confirmed speech. A cough or short "hey" must not barge in; sustained speech must, immediately at confirm — not at end-of-speech. Do not glue those gates or retune one side without the dual test `cough_and_hey_do_not_barge_in_sustained_noisy_speech_does`. Details: [docs/mobile-apps.md](docs/mobile-apps.md) (TTS barge-in dual invariant).
