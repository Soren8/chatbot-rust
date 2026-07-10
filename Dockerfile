# syntax=docker/dockerfile:1.7

FROM debian:bookworm-slim AS rust-tools

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    ca-certificates \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

ENV CARGO_HOME=/app/.cargo
RUN mkdir -p /app/.cargo
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal --default-toolchain stable
RUN /app/.cargo/bin/rustup component add rustfmt
ENV PATH="/app/.cargo/bin:$PATH"

# Fetch dependencies (only invalidates on Cargo.toml/lock changes)
FROM rust-tools AS rust-deps
ARG RUST_BUILD_PROFILE=debug
ENV RUST_BUILD_PROFILE=${RUST_BUILD_PROFILE}

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
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

RUN --mount=type=cache,target=/app/.cargo/registry \
    --mount=type=cache,target=/app/.cargo/git \
    cargo fetch

# Build the Rust server (invalidates when source changes, but reuses dep cache)
FROM rust-deps AS rust-build

COPY chatbot-core /build/chatbot-core
COPY chatbot-server /build/chatbot-server
COPY chatbot-test-support /build/chatbot-test-support
COPY static /build/static

RUN --mount=type=cache,target=/app/.cargo/registry \
    --mount=type=cache,target=/app/.cargo/git \
    --mount=type=cache,target=/app/.cargo/target \
    sh -ec '\
      export CARGO_TARGET_DIR=/app/.cargo/target; \
      if [ "$RUST_BUILD_PROFILE" = "debug" ]; then \
        cargo build -p chatbot-server; \
        profile_dir=debug; \
      else \
        cargo build --profile "$RUST_BUILD_PROFILE" -p chatbot-server; \
        profile_dir="$RUST_BUILD_PROFILE"; \
      fi; \
      mkdir -p "/build/target/$profile_dir"; \
      cp "/app/.cargo/target/$profile_dir/chatbot-server" "/build/target/$profile_dir/chatbot-server" \
    '

# Test image with cargo available
FROM rust-tools AS test
# Toolchain lives outside /app so the dev bind-mount (./:/app) cannot hide cargo on CI.
ENV CARGO_HOME=/opt/cargo
ENV PATH="/opt/cargo/bin:$PATH"
RUN mkdir -p /opt/cargo && cp -a /app/.cargo/. /opt/cargo/
WORKDIR /app
COPY Cargo.toml Cargo.lock /app/
COPY chatbot-core /app/chatbot-core
COPY chatbot-server /app/chatbot-server
COPY chatbot-test-support /app/chatbot-test-support
COPY static /app/static
RUN mkdir -p /app/data
RUN touch /app/.config.yml
ENV CHATBOT_STATIC_ROOT="/app/static"
ENV CARGO_TARGET_DIR=/app/.cargo/target

# Production image with Axum binary
FROM debian:bookworm-slim AS prod
ARG RUST_BUILD_PROFILE=debug
ENV RUST_BUILD_PROFILE=${RUST_BUILD_PROFILE}

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=rust-build /build/target/${RUST_BUILD_PROFILE}/chatbot-server /usr/local/bin/chatbot-server
COPY static /app/static
ENV CHATBOT_STATIC_ROOT="/app/static"

# Default to Axum server; bind address is configurable via CHATBOT_BIND_ADDR
CMD ["chatbot-server"]
