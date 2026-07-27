#!/usr/bin/env bash
# Run the integration test suite via the compose `tests` service.
#
# From a host checkout:
#   ./scripts/run-tests.sh
#   ./scripts/run-tests.sh cargo test -p chatbot-core
#
# From an agent sandbox (docker-outside-of-docker), bind mounts must use the
# *host* path of this repo. This wrapper sets HOST_PROJECT_DIR when unset:
#   HOST_PROJECT_DIR  Absolute host path of the chatbot-rust repo root.
#                     Default: auto-detected via scripts/resolve-host-path.sh
#                     Override: export HOST_PROJECT_DIR=/path/on/host
#
# Compose still accepts a plain relative layout when HOST_PROJECT_DIR is left
# unset and you run on the host (`${HOST_PROJECT_DIR:-.}` → `.`).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -z "${HOST_PROJECT_DIR:-}" ]]; then
  # shellcheck disable=SC1091
  HOST_PROJECT_DIR="$("${ROOT}/scripts/resolve-host-path.sh" "${ROOT}")"
  export HOST_PROJECT_DIR
fi

# Ensure bind-mount targets exist on the host path (daemon creates root-owned
# dirs otherwise when the path is missing).
mkdir -p \
  "${ROOT}/temp/test-logs" \
  "${ROOT}/temp/.cargo/registry" \
  "${ROOT}/temp/.cargo/git" \
  "${ROOT}/temp/.cargo/target" \
  "${ROOT}/temp/.docker/tests"

echo "run-tests: HOST_PROJECT_DIR=${HOST_PROJECT_DIR}"

# Avoid compose warnings for unrelated services that interpolate SECRET_KEY.
export SECRET_KEY="${SECRET_KEY:-test_secret_key_for_security_tests}"

if [[ $# -eq 0 ]]; then
  exec docker compose run --rm tests
fi
exec docker compose run --rm tests "$@"
