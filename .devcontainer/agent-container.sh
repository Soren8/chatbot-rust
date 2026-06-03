#!/usr/bin/env bash
# Start the agent-safe dev environment with Docker only (no npm devcontainers CLI).
#
# Usage:
#   .devcontainer/agent-container.sh up      # build image + start detached container
#   .devcontainer/agent-container.sh shell   # interactive bash in /workspace
#   .devcontainer/agent-container.sh grok    # run Grok Build TUI
#   .devcontainer/agent-container.sh exec CMD...  # run a one-off command
#   .devcontainer/agent-container.sh down    # stop and remove container
#   .devcontainer/agent-container.sh build   # rebuild image only
#
# Optional alias (add to ~/.bashrc):
#   alias agent-dev='/path/to/chatbot-rust/.devcontainer/agent-container.sh'
set -euo pipefail

readonly IMAGE_NAME="chatbot-rust-agent-dev:local"
readonly CONTAINER_NAME="chatbot-rust-agent-dev"
readonly CARGO_REGISTRY_VOLUME="chatbot-rust-cargo-registry"
readonly CARGO_GIT_VOLUME="chatbot-rust-cargo-git"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

die() {
  echo "agent-container: $*" >&2
  exit 1
}

require_docker() {
  command -v docker >/dev/null 2>&1 || die "docker is not installed or not on PATH"
  docker info >/dev/null 2>&1 || die "docker daemon is not running"
}

docker_socket_gid() {
  if [[ -S /var/run/docker.sock ]]; then
    stat -c '%g' /var/run/docker.sock
    return
  fi
  getent group docker 2>/dev/null | cut -d: -f3 || die "cannot resolve docker group GID"
}

container_running() {
  docker inspect -f '{{.State.Running}}' "${CONTAINER_NAME}" 2>/dev/null | grep -q true
}

container_exists() {
  docker inspect "${CONTAINER_NAME}" >/dev/null 2>&1
}

build_image() {
  echo "agent-container: building ${IMAGE_NAME} (uid=$(id -u) gid=$(id -g))..."
  docker build \
    --build-arg "USER_UID=$(id -u)" \
    --build-arg "USER_GID=$(id -g)" \
    -f "${SCRIPT_DIR}/Dockerfile" \
    -t "${IMAGE_NAME}" \
    "${SCRIPT_DIR}"
}

ensure_volumes() {
  docker volume inspect "${CARGO_REGISTRY_VOLUME}" >/dev/null 2>&1 \
    || docker volume create "${CARGO_REGISTRY_VOLUME}" >/dev/null
  docker volume inspect "${CARGO_GIT_VOLUME}" >/dev/null 2>&1 \
    || docker volume create "${CARGO_GIT_VOLUME}" >/dev/null
}

run_post_create() {
  docker exec \
    -u agent \
    -w /workspace \
    -e CONTAINER_WORKSPACE=/workspace \
    -e INSTALL_GROK=1 \
    -e GROK_SANDBOX=chatbot-agent \
    "${CONTAINER_NAME}" \
    bash .devcontainer/scripts/post-create.sh
}

start_container() {
  [[ -f "${REPO_ROOT}/.config.yml.example" ]] \
    || die "missing ${REPO_ROOT}/.config.yml.example (required for config overlay)"

  local docker_gid
  docker_gid="$(docker_socket_gid)"

  ensure_volumes

  if container_exists; then
    if container_running; then
      echo "agent-container: ${CONTAINER_NAME} already running"
      return 0
    fi
    echo "agent-container: starting existing ${CONTAINER_NAME}..."
    docker start "${CONTAINER_NAME}" >/dev/null
    return 0
  fi

  echo "agent-container: creating ${CONTAINER_NAME}..."
  docker run -d \
    --name "${CONTAINER_NAME}" \
    --init \
    --hostname "${CONTAINER_NAME}" \
    --group-add "${docker_gid}" \
    -v "${REPO_ROOT}:/workspace" \
    -v "${CARGO_REGISTRY_VOLUME}:/home/agent/.cargo/registry" \
    -v "${CARGO_GIT_VOLUME}:/home/agent/.cargo/git" \
    -v "${REPO_ROOT}/.devcontainer/stubs/.env:/workspace/.env:ro" \
    -v "${REPO_ROOT}/.config.yml.example:/workspace/.config.yml:ro" \
    -v "${REPO_ROOT}/.devcontainer/stubs/data:/workspace/data:ro" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -w /workspace \
    -e CARGO_HOME=/home/agent/.cargo \
    -e CARGO_TARGET_DIR=/workspace/temp/.cargo/target \
    -e RUSTUP_HOME=/home/agent/.rustup \
    -e GROK_SANDBOX=chatbot-agent \
    -e INSTALL_GROK=1 \
    -e "PATH=/home/agent/.grok/bin:/home/agent/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    "${IMAGE_NAME}" \
    sleep infinity

  run_post_create
}

cmd_up() {
  require_docker
  build_image
  start_container
  echo "agent-container: ready. Run: ${BASH_SOURCE[0]} grok"
}

cmd_down() {
  require_docker
  if container_exists; then
    docker rm -f "${CONTAINER_NAME}" >/dev/null
    echo "agent-container: removed ${CONTAINER_NAME}"
  else
    echo "agent-container: ${CONTAINER_NAME} not found"
  fi
}

exec_agent() {
  local tty_flags=()
  if [[ -t 0 ]]; then
    tty_flags=(-it)
  fi
  docker exec "${tty_flags[@]}" \
    -u agent \
    -w /workspace \
    -e GROK_SANDBOX=chatbot-agent \
    -e "PATH=/home/agent/.grok/bin:/home/agent/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    "${CONTAINER_NAME}" \
    "$@"
}

cmd_shell() {
  require_docker
  container_running || die "container not running; run: ${BASH_SOURCE[0]} up"
  exec_agent bash -l
}

cmd_grok() {
  require_docker
  container_running || die "container not running; run: ${BASH_SOURCE[0]} up"
  exec_agent grok "$@"
}

cmd_exec() {
  require_docker
  container_running || die "container not running; run: ${BASH_SOURCE[0]} up"
  [[ $# -gt 0 ]] || die "usage: ${BASH_SOURCE[0]} exec COMMAND [ARGS...]"
  exec_agent "$@"
}

usage() {
  sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'
  exit "${1:-0}"
}

main() {
  local cmd="${1:-}"
  shift || true
  case "${cmd}" in
    up|start) cmd_up ;;
    down|stop|rm) cmd_down ;;
    build) require_docker; build_image ;;
    shell|sh|bash) cmd_shell ;;
    grok) cmd_grok "$@" ;;
    exec) cmd_exec "$@" ;;
    -h|--help|help|"") usage 0 ;;
    *) die "unknown command: ${cmd} (try --help)" ;;
  esac
}

main "$@"