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
RUN mkdir -p rust/chatbot-core/src rust/chatbot-server/src rust/chatbot-test-support/src
RUN printf 'fn main() {}\n' > rust/chatbot-server/src/main.rs \
    && printf '' > rust/chatbot-server/src/lib.rs \
    && touch rust/chatbot-core/src/lib.rs \
    && touch rust/chatbot-test-support/src/lib.rs

COPY rust/Cargo.toml rust/Cargo.lock ./rust/
COPY rust/chatbot-core/Cargo.toml ./rust/chatbot-core/
COPY rust/chatbot-server/Cargo.toml ./rust/chatbot-server/
COPY rust/chatbot-test-support/Cargo.toml ./rust/chatbot-test-support/

WORKDIR /build/rust
RUN cargo fetch

COPY rust /build/rust
COPY app/templates /build/app/templates
COPY app/static /build/app/static

RUN if [ "${RUST_BUILD_PROFILE}" = "debug" ]; then \
        cargo build -p chatbot-server; \
    else \
        cargo build --profile "${RUST_BUILD_PROFILE}" -p chatbot-server; \
    fi

# Test image with cargo available
FROM rust-tools AS test
WORKDIR /app
COPY rust /app/rust
COPY app/templates /app/app/templates
COPY app/static /app/app/static
RUN mkdir -p /app/data
RUN touch /app/.config.yml
ENV CHATBOT_STATIC_ROOT="/app/app/static"

# Production image with Axum binary
FROM debian:bookworm-slim AS prod
ARG RUST_BUILD_PROFILE=debug
ENV RUST_BUILD_PROFILE=${RUST_BUILD_PROFILE}

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=rust-build /build/rust/target/${RUST_BUILD_PROFILE}/chatbot-server /usr/local/bin/chatbot-server
COPY app/static /app/static
ENV CHATBOT_STATIC_ROOT="/app/static"

# Default to Axum server; bind address is configurable via CHATBOT_BIND_ADDR
CMD ["chatbot-server"]
