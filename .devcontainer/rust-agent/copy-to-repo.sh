#!/usr/bin/env bash
# Copy the rust-agent devcontainer template into another repository.
# Usage: ./copy-to-repo.sh /path/to/other-rust-repo
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 /path/to/target-repo" >&2
  exit 1
fi

TARGET="$(cd "$1" && pwd)"
SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE_ROOT="${SOURCE}"

if [[ ! -f "${TEMPLATE_ROOT}/Dockerfile" ]]; then
  echo "ERROR: run from a checkout that has .devcontainer/Dockerfile" >&2
  exit 1
fi

mkdir -p "${TARGET}/.devcontainer"/{rust-agent,stubs/data,scripts}

cp -a "${TEMPLATE_ROOT}/Dockerfile" "${TARGET}/.devcontainer/"
cp -a "${TEMPLATE_ROOT}/rust-agent/"*.sh "${TARGET}/.devcontainer/rust-agent/"
cp -a "${TEMPLATE_ROOT}/rust-agent/"*.json "${TARGET}/.devcontainer/rust-agent/"
cp -a "${TEMPLATE_ROOT}/rust-agent/README.md" "${TARGET}/.devcontainer/rust-agent/"
cp -a "${TEMPLATE_ROOT}/scripts/post-create.sh" "${TARGET}/.devcontainer/scripts/"

if [[ ! -f "${TARGET}/.devcontainer/stubs/.env" ]]; then
  printf '%s\n' '# Empty stub — mount over host .env in devcontainer.' > "${TARGET}/.devcontainer/stubs/.env"
fi
touch "${TARGET}/.devcontainer/stubs/data/.gitkeep"

if [[ ! -f "${TARGET}/.devcontainer/devcontainer.json" ]]; then
  cp "${TEMPLATE_ROOT}/rust-agent/devcontainer.base.json" "${TARGET}/.devcontainer/devcontainer.json"
  echo "Created ${TARGET}/.devcontainer/devcontainer.json — edit PROJECT_NAME, mounts, and verify script."
else
  echo "Kept existing ${TARGET}/.devcontainer/devcontainer.json"
fi

if [[ ! -f "${TARGET}/.devcontainer/scripts/verify-secret-overlays.sh" ]]; then
  cp "${TEMPLATE_ROOT}/scripts/verify-secret-overlays.sh" "${TARGET}/.devcontainer/scripts/"
  echo "Copied verify-secret-overlays.sh — customize for your secret paths."
fi

chmod +x "${TARGET}/.devcontainer/rust-agent/"*.sh "${TARGET}/.devcontainer/scripts/"*.sh 2>/dev/null || true

echo "Done. Next: edit devcontainer.json mounts and AGENTS.md in ${TARGET}"