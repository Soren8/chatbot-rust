#!/usr/bin/env bash
# Generic post-create hook for rust-agent devcontainers.
set -euo pipefail

WORKSPACE="${CONTAINER_WORKSPACE:-/workspace}"
cd "${WORKSPACE}"

echo "[devcontainer] rust-agent post-create (workspace: ${WORKSPACE})"

# Persist cargo caches under temp/ per project conventions
mkdir -p "${WORKSPACE}/temp/.cargo/target"

# Git safety when the repo is bind-mounted from the host
if command -v git >/dev/null 2>&1; then
  git config --global --add safe.directory "${WORKSPACE}" 2>/dev/null || true
fi

# Optional: install Grok Build (primary target CLI)
if [[ "${INSTALL_GROK:-1}" != "0" ]]; then
  bash "$(dirname "${BASH_SOURCE[0]}")/install-grok.sh"
fi

# Verify secret overlays when the project provides check script
CHECK_SCRIPT="${WORKSPACE}/.devcontainer/scripts/verify-secret-overlays.sh"
if [[ -f "${CHECK_SCRIPT}" ]]; then
  bash "${CHECK_SCRIPT}"
fi

echo "[devcontainer] Ready. Isolation is this container + secret overlays; run any agent CLI inside."