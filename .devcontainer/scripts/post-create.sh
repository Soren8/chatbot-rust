#!/usr/bin/env bash
set -euo pipefail
export CONTAINER_WORKSPACE=/workspace
export INSTALL_GROK=1
exec bash /workspace/.devcontainer/rust-agent/post-create.sh