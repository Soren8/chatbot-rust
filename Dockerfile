# syntax=docker/dockerfile:1.7

FROM debian:bookworm-slim AS rust-tools

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    ca-certificates \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal --default-toolchain stable
RUN /root/.cargo/bin/rustup component add rustfmt
ENV PATH="/root/.cargo/bin:$PATH"

# Build the Rust server
FROM rust-tools AS rust-build
ARG RUST_BUILD_PROFILE=debug
ENV RUST_BUILD_PROFILE=${RUST_BUILD_PROFILE}

WORKDIR /build
RUN mkdir -p chatbot-core/src chatbot-server/src chatbot-test-support/src
RUN printf 'fn main() {}\n' > chatbot-server/src/main.rs \
    && printf '' > chatbot-server/src/lib.rs \
    && touch chatbot-core/src/lib.rs \
    && touch chatbot-test-support/src/lib.rs

COPY Cargo.toml Cargo.lock ./
COPY chatbot-core/Cargo.toml ./chatbot-core/
COPY chatbot-server/Cargo.toml ./chatbot-server/
COPY chatbot-test-support/Cargo.toml ./chatbot-test-support/

RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    cargo fetch

COPY chatbot-core /build/chatbot-core
COPY chatbot-server /build/chatbot-server
COPY chatbot-test-support /build/chatbot-test-support
COPY static /build/static

RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/build/target-cache \
    sh -ec '\
      export CARGO_TARGET_DIR=/build/target-cache; \
      if [ "$RUST_BUILD_PROFILE" = "debug" ]; then \
        cargo build -p chatbot-server; \
        profile_dir=debug; \
      else \
        cargo build --profile "$RUST_BUILD_PROFILE" -p chatbot-server; \
        profile_dir="$RUST_BUILD_PROFILE"; \
      fi; \
      mkdir -p "/build/target/$profile_dir"; \
      cp "/build/target-cache/$profile_dir/chatbot-server" "/build/target/$profile_dir/chatbot-server" \
    '

# Test image with cargo available
FROM rust-tools AS test
WORKDIR /app
COPY Cargo.toml Cargo.lock /app/
COPY chatbot-core /app/chatbot-core
COPY chatbot-server /app/chatbot-server
COPY chatbot-test-support /app/chatbot-test-support
COPY static /app/static
RUN mkdir -p /app/data
RUN touch /app/.config.yml
ENV CHATBOT_STATIC_ROOT="/app/static"

# Production image with Axum binary
FROM debian:bookworm-slim AS prod
ARG RUST_BUILD_PROFILE=debug
ENV RUST_BUILD_PROFILE=${RUST_BUILD_PROFILE}

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=rust-build /build/target/${RUST_BUILD_PROFILE}/chatbot-server /usr/local/bin/chatbot-server
COPY static /app/static
ENV CHATBOT_STATIC_ROOT="/app/static"

# Default to Axum server; bind address is configurable via CHATBOT_BIND_ADDR
CMD ["chatbot-server"]
