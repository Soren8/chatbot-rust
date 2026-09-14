# syntax=docker/dockerfile:1.7

FROM rust:1.98.0-slim-bookworm@sha256:1469a27c125cb5a3aebfa4f4e4665d935b02fb72cc093b2c974b3d740e43f157 AS rust-tools

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    libopus-dev \
    && rm -rf /var/lib/apt/lists/*

RUN rustup component add rustfmt

# Fetch dependencies (only invalidates on Cargo.toml/lock changes)
FROM rust-tools AS rust-deps
ARG RUST_BUILD_PROFILE=debug
ENV RUST_BUILD_PROFILE=${RUST_BUILD_PROFILE}

WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY chatbot-core/Cargo.toml ./chatbot-core/
COPY chatbot-server/Cargo.toml ./chatbot-server/
COPY chatbot-test-support/Cargo.toml ./chatbot-test-support/

# Create stub sources so cargo can parse manifests for fetch (some crates like
# chatbot-test-support have no src/ until full copy later)
RUN mkdir -p chatbot-core/src chatbot-server/src chatbot-test-support/src \
    && printf 'fn main() {}\n' > chatbot-server/src/main.rs \
    && printf '' > chatbot-server/src/lib.rs \
    && touch chatbot-core/src/lib.rs \
    && touch chatbot-test-support/src/lib.rs

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo fetch

# Build the Rust server (invalidates when source changes, but reuses dep cache)
FROM rust-deps AS rust-build

COPY chatbot-core /build/chatbot-core
COPY chatbot-server /build/chatbot-server
COPY chatbot-test-support /build/chatbot-test-support
COPY static /build/static

# `COPY` preserves source mtimes while the cache-mounted target dir persists
# compiled artifacts across builds. Cargo's mtime freshness check would then
# treat a copied source file as older than a stale artifact and skip the
# recompile (rust-lang/cargo#9312), linking e.g. an old chatbot-core rlib that
# lacks APIs the rebuilt chatbot-server expects. Advance the workspace source
# mtimes past any warm cache entry before cargo reads them.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/local/cargo/target \
    sh -ec '\
      find chatbot-core chatbot-server chatbot-test-support -type f -exec touch {} +; \
      export CARGO_TARGET_DIR=/usr/local/cargo/target; \
      if [ "$RUST_BUILD_PROFILE" = "debug" ]; then \
        cargo build -p chatbot-server; \
        profile_dir=debug; \
      else \
        cargo build --profile "$RUST_BUILD_PROFILE" -p chatbot-server; \
        profile_dir="$RUST_BUILD_PROFILE"; \
      fi; \
      mkdir -p "/build/target/$profile_dir"; \
      cp "/usr/local/cargo/target/$profile_dir/chatbot-server" "/build/target/$profile_dir/chatbot-server" \
    '

# Test image with cargo available
FROM rust-tools AS test
# Toolchain lives outside /app so the dev bind-mount (./:/app) cannot hide cargo on CI.
ENV CARGO_HOME=/opt/cargo
ENV PATH="/usr/local/cargo/bin:${PATH}"
WORKDIR /app
COPY Cargo.toml Cargo.lock rust-toolchain.toml /app/
COPY chatbot-core/Cargo.toml /app/chatbot-core/
COPY chatbot-server/Cargo.toml /app/chatbot-server/
COPY chatbot-test-support/Cargo.toml /app/chatbot-test-support/
# Seed the run-phase cargo home (/opt/cargo) from the persistent build
# caches. The executor prepare step runs `cargo fetch` with
# CARGO_HOME=/opt/cargo and network; with a warm builder this is already
# complete, so prepare downloads nothing. Keyed on manifests only, so this
# layer survives source changes. If the builder caches are cold (first-ever
# build) the seed copies nothing and prepare falls back to downloading.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    sh -ec '\
      mkdir -p /opt/cargo; \
      cp -a /usr/local/cargo/registry /opt/cargo/ 2>/dev/null || true; \
      cp -a /usr/local/cargo/git /opt/cargo/ 2>/dev/null || true; \
    '
COPY chatbot-core /app/chatbot-core
COPY chatbot-server /app/chatbot-server
COPY chatbot-test-support /app/chatbot-test-support
COPY static /app/static
# Integration tests inspect Android sources with compile-time include_str! calls.
COPY android/app/src /app/android/app/src
COPY .config.yml.example /app/.config.yml.example
# docker_build.rs guards the image build recipe itself.
COPY Dockerfile /app/Dockerfile
ENV CHATBOT_STATIC_ROOT="/app/static"
ENV CARGO_TARGET_DIR=/app/.cargo/target

# The test run mounts an executor-managed persistent Cargo target cache at
# $CARGO_TARGET_DIR, so compiled artifacts survive between jobs without being
# exported in the image. Keep this stage to sources and toolchain only.
RUN mkdir -p /app/.cargo/target /app/data
RUN touch /app/.config.yml

# Production image with Axum binary
FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 AS prod
ARG RUST_BUILD_PROFILE=debug
ENV RUST_BUILD_PROFILE=${RUST_BUILD_PROFILE}
# Minimum config schema version this image requires; read by the deploy
# side (iac) via `docker image inspect` to gate config/image ordering.
ARG CONFIG_VERSION=1
LABEL chat.config_version=${CONFIG_VERSION}

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl libopus0 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=rust-build /build/target/${RUST_BUILD_PROFILE}/chatbot-server /usr/local/bin/chatbot-server
COPY static /app/static
ENV CHATBOT_STATIC_ROOT="/app/static"

# Default to Axum server; bind address is configurable via CHATBOT_BIND_ADDR
CMD ["chatbot-server"]
