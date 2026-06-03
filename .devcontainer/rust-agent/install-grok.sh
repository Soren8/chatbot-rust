#!/usr/bin/env bash
# Install Grok Build CLI for the devcontainer user (idempotent).
set -euo pipefail

if command -v grok >/dev/null 2>&1; then
  echo "[devcontainer] grok already installed: $(grok --version 2>/dev/null || true)"
  exit 0
fi

echo "[devcontainer] Installing Grok Build CLI..."
curl -fsSL https://x.ai/cli/install.sh | bash

if command -v grok >/dev/null 2>&1; then
  echo "[devcontainer] grok installed: $(grok --version 2>/dev/null || true)"
else
  echo "[devcontainer] WARNING: grok not on PATH after install; open a new shell or add ~/.grok/bin to PATH" >&2
fi