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

# Tests
.devcontainer/agent-container.sh exec docker compose run --rm tests cargo test

# Stop
.devcontainer/agent-container.sh down
```

Optional alias in `~/.bashrc`:

```bash
alias agent-dev='/home/malakar/github/chatbot-rust/.devcontainer/agent-container.sh'
# then: agent-dev up && agent-dev shell
```

**Full stack with host `.env`:** on the host (not in the agent container):

```bash
docker compose --progress plain up --build -d
```

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