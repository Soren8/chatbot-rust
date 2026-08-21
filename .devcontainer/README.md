# Agent-safe dev container

**The Docker container is the sandbox.** Isolation is system-level (container + secret
bind-mount overlays) for **any** coding agent — not a Grok-only Landlock/bwrap profile.

Host secret files are masked by bind-mount overlays. Use **Docker only** via
`agent-container.sh` (no npm devcontainers CLI).

## Usage

```bash
# From repo root — first time builds the image and runs post-create
.devcontainer/agent-container.sh up

# Interactive shell (run whatever agent you want)
.devcontainer/agent-container.sh shell

# Convenience: Grok TUI (optional; installed when INSTALL_GROK=1)
.devcontainer/agent-container.sh grok

# Integration tests (inside the container)
docker compose run --rm tests

# Stop
.devcontainer/agent-container.sh down
```

Optional alias in `~/.bashrc`:

```bash
alias agent-dev='$PWD/.devcontainer/agent-container.sh'  # run from repo root
# then: agent-dev up && agent-dev shell
```

**Full stack (webserver / voice-service):** only on the **host**, with real `.env` — not from the agent container. Agents must not run live compose up/build; ask the user to redeploy when needed. See root `AGENTS.md`.

## Cursor / VS Code (optional)

Command Palette → **Dev Containers: Reopen in Container** uses the same `devcontainer.json` definition.

## What is hidden inside the container

| Host path | Inside dev container |
|-----------|----------------------|
| `.env` | Empty stub (`.devcontainer/stubs/.env`) |
| `.config.yml` | Read-only `.config.yml.example` |
| `data/` | Empty stub directory |

`post-create` runs `scripts/verify-secret-overlays.sh` and **fails** if overlays did not apply.

Agents using **Read/grep** never see real secrets. **Compose** invoked from `/workspace` reads the stub `.env`, which is usually what you want for agents; use the host terminal for `compose up` when services need `${SECRET_KEY}` and provider keys from `.env`.

## Docker

- **Host socket** via [docker-outside-of-docker](https://github.com/devcontainers/features/tree/main/src/docker-outside-of-docker) (`enableNonRootDocker` so user `agent` can run `docker`).
- **`tests` service** — does not depend on workspace `.env` (keys are set in `docker-compose.yml`).
- **GPU / voice-service** — still runs on the host daemon; no extra GPU wiring in the devcontainer.

### Running the integration suite inside the agent container

```bash
docker compose run --rm tests
```

Compose bind mounts are resolved by the host daemon. The sandbox sets `HOST_PROJECT_DIR` to this repo’s host path. Default is `.` on a normal host checkout. Do not hardcode machine-specific paths.

Logs land under `temp/test-logs/`.

## Layout

| Path | Purpose |
|------|---------|
| `Dockerfile` | Reusable Rust + `agent` user image |
| `devcontainer.json` | This repo’s overlays and settings |
| `rust-agent/` | Template files for other Rust projects |
| `stubs/` | Empty placeholder files mounted over secrets |
| `scripts/` | Post-create and overlay verification |

## Reuse in another Rust repo

See [rust-agent/README.md](rust-agent/README.md).

## Isolation model

1. **Docker container** — process/filesystem boundary from the host (all agents)
2. **Bind-mount secret overlays** — real `.env` / `.config.yml` / `data/` never visible inside
3. `.cursorignore` (optional; Cursor indexing only)

Do **not** rely on per-agent sandbox flags for safety inside this container.