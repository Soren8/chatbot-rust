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
5. Add `.grok/sandbox.toml` `deny` entries matching the same paths (copy from chatbot-rust).
6. Add `.cursorignore` entries for the same paths.

## Grok Build

- `install-grok.sh` runs on post-create when `INSTALL_GROK=1` (default).
- Set `GROK_SANDBOX=chatbot-agent` in `containerEnv` and commit `.grok/sandbox.toml`.
- Run: `grok` or `grok --sandbox chatbot-agent`

## Other CLI agents

Works with any agent that uses the devcontainer filesystem:

```bash
# Aider, Claude Code, opencode, etc.
cd /workspace
# agent command here
```

Mount overlays apply to **all** tools in the container, not only Grok.

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