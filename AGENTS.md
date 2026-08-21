# AGENTS.md - Development Guide

Project-specific agent instructions for chatbot-rust. User-level policy lives in `~/.grok/AGENTS.md`.

## Agent devcontainer (secret-safe)

- **The Docker container is the sandbox** for any coding agent (Grok, Claude, Cursor, Aider, …). Isolation is container + secret bind-mount overlays — not per-agent Landlock/bwrap flags.
- Start with `.devcontainer/agent-container.sh up`, then `.devcontainer/agent-container.sh shell` (or `grok`, or any other agent CLI). See `.devcontainer/README.md`.
- Host `.env` / `.config.yml` / `data/` are masked for **every** process inside the container.
- **Docker from the devcontainer:** the host Docker socket is available for the **`tests` service only** (see **Running tests**). The `tests` service does not need workspace `.env`.
- **Live stack (`webserver`, `voice-service`):** agents must **not** run `docker compose up`, `build`, or recreate for these services. Sandbox `.env` / `.config.yml` are stubs/overlays, so compose from here would inject empty secrets and wrong mounts. After code or `static/` changes that need a running server, **tell the user** to rebuild/restart on the **host** (they have real `.env` and bind paths). Do not paste or invent host deploy commands as something the agent will run.

## Running tests

**Always use Docker** for the full suite. Do not run `cargo test` on the host/agent toolchain as the primary gate — use the compose `tests` service.

### Preferred (host or agent sandbox)

From the repo root:

```bash
./scripts/run-tests.sh
```

Optional args replace the default command (same as `docker compose run --rm tests …`):

```bash
./scripts/run-tests.sh cargo test -p chatbot-core
./scripts/run-tests.sh cargo test --test login -- --nocapture
```

First-party `static/*.js` is parsed by the `js_syntax` cargo test (`oxc_parser`, locked in `Cargo.lock`). Do not install Node/npm for this, and do not add hand-rolled brace scanners.

### Why `run-tests.sh` (devcontainer / agent sandbox)

The agent environment uses **docker-outside-of-docker** (CLI in the container, daemon on the host). Compose **bind mounts** are resolved by the host daemon. A bare `./` volume from inside the sandbox points at a path that often does **not** match this checkout on the host, so the tests container may miss `Cargo.toml` and sources.

`./scripts/run-tests.sh` fixes that by setting **`HOST_PROJECT_DIR`** to the host path of this repo (via `scripts/resolve-host-path.sh`) before invoking compose. Never hardcode machine-specific absolute paths in the repo or in docs.

| Variable | Meaning |
|----------|---------|
| `HOST_PROJECT_DIR` | Host-absolute path of the `chatbot-rust` repo root for bind mounts. Default in compose: `.` (fine on a normal host checkout). In the agent sandbox, set automatically by `run-tests.sh`. Override only if auto-detect fails: `export HOST_PROJECT_DIR=…` |

### Manual equivalent

```bash
HOST_PROJECT_DIR="$(./scripts/resolve-host-path.sh .)" docker compose run --rm tests
```

On a **host** checkout (not inside the agent container), plain compose also works because `.` is already the host path:

```bash
docker compose run --rm tests
```

Logs: `temp/test-logs/`. Cargo/build caches for the suite: `temp/.cargo/`, `temp/.docker/tests/`.

## Build & Run Commands

- Integration tests (agent or host): `./scripts/run-tests.sh` (see **Running tests**)
- Do not run `cargo test` / app binaries outside Docker as the verification gate.
- Do **not** build, up, or restart the live `webserver` / `voice-service` stack from the agent sandbox. Ask the **user** to do that on the host when a live deploy is needed.

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
- Do not read `.env`, `.config.yml`, or `data/` unless the user explicitly asks you to; in the devcontainer these paths are stubs or examples only.
- The `/tts` endpoint uses a two-step "Pre-sign" pattern for browser compatibility: a `POST` to `/tts` submits text and receives a token, followed by a `GET /tts_stream/{token}` for native browser streaming. `POST /tts` requires CSRF and respects `tts_access` (`anyone` | `authenticated` | `premium`; default `anyone`). Do not reintroduce unauthenticated webserver `/api/tts*` routes; the voice-service TTS HTTP API is internal (webserver → GPU), not a public product API.
