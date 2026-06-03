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
    git \
    libssl-dev \
    pkg-config \
    sudo \
    && rm -rf /var/lib/apt/lists/*

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