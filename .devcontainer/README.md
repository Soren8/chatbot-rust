# Agent-safe dev container

Coding agents (Grok Build, Cursor, Claude Code, etc.) run in a container where **host secret files are masked** by bind-mount overlays. The app itself still runs via `docker compose` on the **host**, where `.env` and `.config.yml` remain available.

## Quick start

1. Install [Dev Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) (Cursor includes this).
2. **Reopen in Container** (Command Palette → `Dev Containers: Reopen in Container`).
3. Inside the container:

```bash
grok --sandbox chatbot-agent
# or rely on GROK_SANDBOX from devcontainer.json:
grok
```

4. On the **host** (normal terminal, not inside the dev container):

```bash
docker compose --progress plain up --build -d
docker compose run --rm tests cargo test
```

## What is hidden inside the container

| Host path | Inside dev container |
|-----------|----------------------|
| `.env` | Empty stub (`.devcontainer/stubs/.env`) |
| `.config.yml` | Read-only `.config.yml.example` |
| `data/` | Empty stub directory |

`post-create` runs `scripts/verify-secret-overlays.sh` and **fails** if overlays did not apply.

## What is intentionally not provided

- **No Docker socket** — agents must not run `docker compose up` for `webserver` here (that would read host `.env`). Run Compose on the host only.
- **No GPU / voice-service** — use host Compose for the full stack.

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