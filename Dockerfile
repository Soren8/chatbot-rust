# Common Python base with virtual environment
FROM python:3.11-slim AS base

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies (shared across stages)
FROM base AS deps
WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Runtime image with application sources
FROM deps AS runtime
COPY app /app/app
COPY tests /app/tests
RUN mkdir -p /app/data
RUN touch /app/.config.yml
ENV PYTHONPATH="/app"
ENV CHATBOT_STATIC_ROOT="/app/app/static"

# Rust-capable toolchain layer (shared between rust-build and tests)
FROM base AS rust-tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    pkg-config \
    libssl-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal --default-toolchain stable
RUN /root/.cargo/bin/rustup component add rustfmt
ENV PATH="/root/.cargo/bin:$PATH"
ENV PYO3_PYTHON="/opt/venv/bin/python"

COPY --from=deps /opt/venv /opt/venv

# Build the Rust server
FROM rust-tools AS rust-build
ARG RUST_BUILD_PROFILE=debug
ENV RUST_BUILD_PROFILE=${RUST_BUILD_PROFILE}

WORKDIR /build
RUN mkdir -p rust/chatbot-core/src rust/chatbot-server/src rust/chatbot-test-support/src
# Provide placeholder targets so `cargo fetch` recognises all workspace members.
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
RUN if [ "${RUST_BUILD_PROFILE}" = "debug" ]; then \
        cargo build -p chatbot-server; \
    else \
        cargo build --profile "${RUST_BUILD_PROFILE}" -p chatbot-server; \
    fi

# Test image with cargo available
FROM rust-tools AS test
COPY --from=deps /opt/venv /opt/venv
RUN pip install --no-cache-dir pytest
WORKDIR /app
COPY app /app/app
COPY tests /app/tests
RUN mkdir -p /app/data
RUN touch /app/.config.yml
ENV PYTHONPATH="/app"
ENV CHATBOT_STATIC_ROOT="/app/app/static"

# Production image with Axum binary
FROM runtime AS prod
ARG RUST_BUILD_PROFILE=debug
ENV RUST_BUILD_PROFILE=${RUST_BUILD_PROFILE}
COPY --from=rust-build /build/rust/target/${RUST_BUILD_PROFILE}/chatbot-server /usr/local/bin/chatbot-server

# Default to Axum server; bind address is configurable via CHATBOT_BIND_ADDR (see docker-compose)
CMD ["chatbot-server"]
