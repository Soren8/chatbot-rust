#!/usr/bin/env bash
# Start the compose `tests` service (full workspace suite inside that image).
# Sets HOST_PROJECT_DIR so bind mounts work under docker-outside-of-docker.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ $# -ne 0 ]]; then
  echo "run-tests: extra args not supported; the tests container always runs the full suite" >&2
  exit 2
fi

if [[ -z "${HOST_PROJECT_DIR:-}" ]]; then
  # shellcheck disable=SC1091
  HOST_PROJECT_DIR="$("${ROOT}/scripts/resolve-host-path.sh" "${ROOT}")"
  export HOST_PROJECT_DIR
fi

mkdir -p \
  "${ROOT}/temp/test-logs" \
  "${ROOT}/temp/.cargo/registry" \
  "${ROOT}/temp/.cargo/git" \
  "${ROOT}/temp/.cargo/target" \
  "${ROOT}/temp/.docker/tests"

echo "run-tests: HOST_PROJECT_DIR=${HOST_PROJECT_DIR}"

export SECRET_KEY="${SECRET_KEY:-test_secret_key_for_security_tests}"

exec docker compose run --rm tests
