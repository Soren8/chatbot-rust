# syntax=docker/dockerfile:1.7

FROM rust:1.98.0-slim-bookworm@sha256:1469a27c125cb5a3aebfa4f4e4665d935b02fb72cc093b2c974b3d740e43f157 AS rust-tools

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
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

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/local/cargo/target \
    sh -ec '\
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
COPY chatbot-core /app/chatbot-core
COPY chatbot-server /app/chatbot-server
COPY chatbot-test-support /app/chatbot-test-support
COPY static /app/static
# Integration tests inspect Android sources with compile-time include_str! calls.
COPY android/app/src /app/android/app/src
COPY .config.yml.example /app/.config.yml.example
RUN mkdir -p /app/data
RUN touch /app/.config.yml
ENV CHATBOT_STATIC_ROOT="/app/static"
ENV CARGO_TARGET_DIR=/app/.cargo/target

# Precompile workspace test targets into the image. The executor runs tests
# in a fresh container with an ephemeral filesystem and no mounts by design,
# so without this every run recompiles all dependencies from scratch (the
# old compose path kept a persistent ./temp/.cargo/target bind-mount; the
# snapshot excludes gitignored temp/ and cannot carry it). Uses the same
# persistent BuildKit caches as rust-build, so only changed crates rebuild
# across runs; the run phase then finds everything fresh and just executes.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/local/cargo/target \
    sh -ec '\
      export CARGO_TARGET_DIR=/usr/local/cargo/target; \
      cargo test --workspace --locked --no-run --manifest-path /app/Cargo.toml; \
      mkdir -p /app/.cargo/target; \
      cp -a /usr/local/cargo/target/. /app/.cargo/target/; \
    '

# Production image with Axum binary
FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 AS prod
ARG RUST_BUILD_PROFILE=debug
ENV RUST_BUILD_PROFILE=${RUST_BUILD_PROFILE}
# Minimum config schema version this image requires; read by the deploy
# side (iac) via `docker image inspect` to gate config/image ordering.
ARG CONFIG_VERSION=1
LABEL chat.config_version=${CONFIG_VERSION}

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=rust-build /build/target/${RUST_BUILD_PROFILE}/chatbot-server /usr/local/bin/chatbot-server
COPY static /app/static
ENV CHATBOT_STATIC_ROOT="/app/static"

# Default to Axum server; bind address is configurable via CHATBOT_BIND_ADDR
CMD ["chatbot-server"]
