# AGENTS.md - Development Guide

## Agent devcontainer (secret-safe)

- **The Docker container is the sandbox** for any coding agent (Grok, Claude, Cursor, Aider, …). Isolation is container + secret bind-mount overlays — not per-agent Landlock/bwrap flags.
- Start with `.devcontainer/agent-container.sh up`, then `.devcontainer/agent-container.sh shell` (or `grok`, or any other agent CLI). See `.devcontainer/README.md`.
- Host `.env` / `.config.yml` / `data/` are masked for **every** process inside the container.
- **Docker Compose** from the devcontainer is supported (host socket): `docker compose build`, `docker compose run --rm tests cargo test`. The `tests` service does not need workspace `.env`.
- For **`docker compose up`** with live secrets from host `.env`, use a **host** terminal (workspace `.env` in the devcontainer is an empty stub).

## Build & Run Commands

- Run Rust integration tests: `docker compose run --rm tests cargo test`
- Run in Docker: `docker compose --progress plain up --build -d`
- Do not attempt to build, run, or test outside of the docker environment.

`static/` and templates are **copied into the image at build time** (hermetic Docker). After changing web UI assets only, rebuild and restart the webserver service:

```bash
docker compose --progress plain up --build -d webserver
```

The Capacitor app loads JS/CSS from the running server; until `webserver` is rebuilt, the phone will keep serving the previous image’s static files.

## Code Style Guidelines
- **Imports**: Standard library first, then third-party, then local modules
- **Error Handling**: Use `anyhow` or `thiserror` for error handling, log errors appropriately with `tracing`
- **Dead code**: Prefer deleting unused code over commenting it out
- **History**: Do not add comments about how code used to be; use git history

## Scratchpad / Temp Files
- Use `temp/` for ephemeral notes (e.g., TODOs) — it is gitignored
- Never reference `temp/` items in commit messages
- Keep `temp/todo.md` updated as you progress

## Refactoring guidelines
- First write concise, focused integration tests that cover existing functionality if needed.
- Make sure those tests pass.
- Write new refactored code that covers all old functionality.
- Ensure the appropriate tests now pass.
- Delete the legacy code (but NEVER delete tests). Tests created during feature implementation or bug fixing are permanent artifacts.

## Bug Fixing Protocol
- When a bug is reported:
  1. Write a new test case that reproduces the bug (it should fail).
  2. Implement the fix.
  3. Run the test again to confirm it passes.

## Scope and user instructions
- Implement only what the user explicitly requested for the current task.
- Do not expand scope on your own — extra endpoints, files, refactors, or "obviously helpful" tweaks are out of scope unless the user asked for them.
- If you believe a related change would help, **stop and ask for confirmation before making it**, even when it seems clearly beneficial. Do not bundle unrequested changes into the same work.
- When unsure whether something is in scope, ask rather than assume.

## Git

- **Commit only — never push.** The user publishes via GitHub Desktop; remote credentials are intentionally unavailable to coding agents.
- Do not run `git push`, `gh` push/release commands, or other operations that modify the remote repository.
- When a task is complete, create a local commit with a concise message. The user will push when ready.

## Important Notes
- Before starting work, read `docs/design.md` and `docs/design-privacy.md` to align with the current architecture and privacy posture.
- Git commit at the completion of each full task (local commit only; see **Git** above).
- ALWAYS run `docker compose --progress plain up --build -d` before running tests to allow the user to reality-check the fix in the running environment while the test suite executes.
- Do not moralize about the user's language or tone.
- Preserve the `temp/.cargo/` cache directory; do not delete it because it stores Rust build artifacts used by other agents. If it is missing, recreate it inside `temp/` (never at repo root).
- Keep Docker build caches under `temp/.docker/`; create that directory inside `temp/` when needed so the repository root stays free of sandbox artefacts.
- Store test run artifacts under `temp/test-logs/`; do not create a top-level `test-logs/` directory.
- Always validate provider configurations before committing
- Use logging (via `tracing`) instead of print statements for debugging
- When asked a question, provide the answer and then stop; do not begin modifying code or implementing changes until the user explicitly provides a "proceed" instruction.
- Treat the task as complete only after all required tests pass and your changes are committed to git.
- Update any relevant docs, checklists or todo lists at the end of a task. Only add content to docs, not checklists or todo lists.
- NEVER add cache busting mechanisms (e.g., query parameters on script tags) unless the user explicitly asks for it. Assume the user knows how to clear their cache.
- When using shell commands like `grep` or `find`, always ensure gitignored directories (e.g., `data/`, `temp/`, `target/`, `.git/`) are excluded to avoid noise and excessive token usage.
- Do not read `.env`, `.config.yml`, or `data/` unless the user explicitly asks you to; in the devcontainer these paths are stubs or examples only.
- The `/tts` endpoint uses a two-step "Pre-sign" pattern for browser compatibility: a `POST` to `/tts` submits text and receives a token, followed by a `GET /tts_stream/{token}` for native browser streaming.
