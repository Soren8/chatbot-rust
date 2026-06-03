# Reusable Rust "agent-safe" devcontainer image.
# Copy this file plus rust-agent/ into other repositories (see rust-agent/README.md).

FROM debian:bookworm-slim

ARG USERNAME=agent
ARG USER_UID=1000
ARG USER_GID=1000

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    docker.io \
    git \
    libssl-dev \
    pkg-config \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Compose v2 plugin (not in bookworm-slim apt); pin release + checksum from GitHub
ARG COMPOSE_VERSION=2.32.4
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "${arch}" in \
      amd64) compose_arch=x86_64 ;; \
      arm64) compose_arch=aarch64 ;; \
      *) echo "unsupported architecture: ${arch}" >&2; exit 1 ;; \
    esac; \
    mkdir -p /usr/libexec/docker/cli-plugins; \
    curl -fsSL \
      "https://github.com/docker/compose/releases/download/v${COMPOSE_VERSION}/docker-compose-linux-${compose_arch}" \
      -o /usr/libexec/docker/cli-plugins/docker-compose; \
    curl -fsSL \
      "https://github.com/docker/compose/releases/download/v${COMPOSE_VERSION}/checksums.txt" \
      -o /tmp/compose-checksums.txt; \
    expected="$(grep "docker-compose-linux-${compose_arch}" /tmp/compose-checksums.txt | awk '{print $1}')"; \
    actual="$(sha256sum /usr/libexec/docker/cli-plugins/docker-compose | awk '{print $1}')"; \
    test "${expected}" = "${actual}"; \
    chmod +x /usr/libexec/docker/cli-plugins/docker-compose; \
    docker compose version

# Rust toolchain (same family as the project Dockerfile)
ENV CARGO_HOME=/home/${USERNAME}/.cargo
ENV RUSTUP_HOME=/home/${USERNAME}/.rustup
ENV PATH="${CARGO_HOME}/bin:${PATH}"

RUN curl -fsSL https://sh.rustup.rs -sSf | sh -s -- -y --profile default --default-toolchain stable \
    && rustup component add rustfmt clippy

RUN groupadd --gid "${USER_GID}" "${USERNAME}" \
    && useradd --uid "${USER_UID}" --gid "${USER_GID}" -m "${USERNAME}" \
    && echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/"${USERNAME}" \
    && chmod 0440 /etc/sudoers.d/"${USERNAME}"

WORKDIR /workspace
RUN mkdir -p /workspace/temp/.cargo/target \
    && chown -R "${USERNAME}:${USERNAME}" /workspace /home/"${USERNAME}"

USER ${USERNAME}