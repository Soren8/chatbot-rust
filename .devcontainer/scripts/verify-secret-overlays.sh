#!/usr/bin/env bash
# Fail post-create if host secret files leaked through the bind mount (overlay misconfiguration).
set -euo pipefail

WORKSPACE="${CONTAINER_WORKSPACE:-/workspace}"
cd "${WORKSPACE}"

fail=0

check_empty_file() {
  local path="$1"
  if [[ ! -f "${path}" ]]; then
    echo "[devcontainer] ERROR: expected overlay file missing: ${path}" >&2
    fail=1
    return
  fi
  if [[ -s "${path}" ]]; then
    # Allow comment-only stubs
    if grep -qvE '^\s*#' "${path}" 2>/dev/null; then
      echo "[devcontainer] ERROR: ${path} is non-empty; secret overlay failed" >&2
      fail=1
    fi
  fi
}

check_empty_file ".env"

if [[ -f ".config.yml" ]]; then
  if grep -qE '^(OPENAI_API_KEY|OPENROUTER_API_KEY|XAI_API_KEY|BRAVE_API_KEY|SECRET_KEY)\s*:' .config.yml 2>/dev/null; then
    echo "[devcontainer] ERROR: .config.yml looks like a live secrets file; expected example overlay" >&2
    fail=1
  fi
fi

if [[ -d "data" ]]; then
  if find data -mindepth 1 ! -name '.gitkeep' -print -quit 2>/dev/null | grep -q .; then
    echo "[devcontainer] ERROR: data/ is not empty; host data may be mounted" >&2
    fail=1
  fi
fi

if [[ "${fail}" -ne 0 ]]; then
  exit 1
fi

echo "[devcontainer] Secret overlay checks passed"