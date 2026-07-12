# rust-agent devcontainer template

Copy this folder (and sibling files) into any Rust workspace to give CLI agents a consistent, secret-safe environment.

## Copy checklist

From a reference repo (e.g. chatbot-rust), copy into `YOUR_REPO/.devcontainer/`:

| File / directory | Required |
|------------------|----------|
| `Dockerfile` | Yes |
| `rust-agent/` (this directory) | Yes |
| `scripts/post-create.sh` | Yes (wrapper) |
| `scripts/verify-secret-overlays.sh` | Customize per repo |
| `stubs/` | Yes (at least `.env` stub) |
| `devcontainer.json` | Start from `devcontainer.base.json` |

## Configure `devcontainer.json`

1. Replace `PROJECT_NAME` and `PROJECT_SLUG` in `devcontainer.base.json`.
2. Append secret overlays to `mounts` (see `secret-overlays.mounts.json` for this repo’s pattern).
3. For each secret file on the host:
   - **Empty stub:** `stubs/.env` → mount over `.env`
   - **Public example:** `.config.yml.example` → mount as `.config.yml`
   - **Empty directory:** `stubs/data/` → mount over `data/`

Example mount entries (string form used by VS Code):

```json
"source=${localWorkspaceFolder}/.devcontainer/stubs/.env,target=/workspace/.env,type=bind,readonly"
```

4. Update `scripts/verify-secret-overlays.sh` with paths and heuristics for your repo.
5. Add `.cursorignore` entries for the same secret paths (editor indexing only).

## Isolation model

**The Docker container is the sandbox** for every agent. Secret isolation is bind-mount
overlays, not per-agent Landlock/bwrap config. Do not set `GROK_SANDBOX` or custom
`deny` profiles as a substitute for the container.

## Agents

Optional Grok install: `install-grok.sh` runs on post-create when `INSTALL_GROK=1`.

Any agent that uses the container filesystem is covered by the same overlays:

```bash
# Aider, Claude Code, Cursor, Grok, opencode, etc.
cd /workspace
# agent command here
```

## Docker Compose (host socket)

`devcontainer.base.json` includes the **docker-outside-of-docker** feature so `agent` can run `docker compose build` and test containers. Copy that `features` block into each repo’s `devcontainer.json`.

Compose run from `/workspace` uses the masked `.env` stub unless you change mounts — fine for CI-style tests; use the host for `compose up` with production secrets.

## Optional: skip Grok install

In `devcontainer.json`:

```json
"containerEnv": {
  "INSTALL_GROK": "0"
}
```

## Optional: extra packages

Extend `.devcontainer/Dockerfile` with project-specific `apt-get` lines (e.g. `protobuf-compiler`, `cmake`).