# Agent-safe dev container

Coding agents (Grok Build, Cursor, Claude Code, etc.) run in a container where **host secret files are masked** by bind-mount overlays. Docker Compose uses the **host** Docker daemon (socket mounted) so agents can build images and run the test container without leaving the dev environment.

## Quick start

1. Install [Dev Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) (Cursor includes this).
2. **Reopen in Container** (Command Palette → `Dev Containers: Reopen in Container`).
3. Inside the container:

```bash
grok --sandbox chatbot-agent
# or rely on GROK_SANDBOX from devcontainer.json:
grok

# Build and integration tests (same as AGENTS.md)
docker compose --progress plain build
docker compose run --rm tests cargo test
```

4. **Full stack with live API keys** (host `.env` / `.config.yml`): run on the host if `compose up` from the devcontainer does not see your secrets (workspace `.env` is a stub here):

```bash
docker compose --progress plain up --build -d
```

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

## Defense in depth

1. Devcontainer overlays (this directory)
2. `.grok/sandbox.toml` `deny` paths (Grok on host or in container)
3. `.cursorignore` (Cursor indexing)
4. Optional: dedicated `aiagent` Linux user + ACLs on the host