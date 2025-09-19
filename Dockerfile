# Base runtime image with app deps
FROM python:3.11-slim AS runtime

# Create a dedicated virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install system dependencies and build essentials
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create a working directory
WORKDIR /app

# Copy requirements and install
COPY requirements.txt /app/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy only the application code
COPY app /app/app

# Create data directory
RUN mkdir -p /app/data

ENV PYTHONPATH="/app"
ENV CHATBOT_STATIC_ROOT="/app/app/static"

# Build the Rust server using the same base environment
FROM runtime AS rust-build
ARG RUST_BUILD_PROFILE=debug
ENV RUST_BUILD_PROFILE=${RUST_BUILD_PROFILE}
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    pkg-config \
    libssl-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal --default-toolchain stable
ENV PATH="/root/.cargo/bin:$PATH"
ENV PYO3_PYTHON="/opt/venv/bin/python"

WORKDIR /build
RUN mkdir -p rust/chatbot-core/src rust/chatbot-server/src
# Provide placeholder targets so `cargo fetch` recognizes the workspace members.
RUN printf 'fn main() {}\n' > rust/chatbot-server/src/main.rs \
    && printf '' > rust/chatbot-server/src/lib.rs \
    && touch rust/chatbot-core/src/lib.rs

COPY rust/Cargo.toml rust/Cargo.lock ./rust/
COPY rust/chatbot-core/Cargo.toml ./rust/chatbot-core/
COPY rust/chatbot-server/Cargo.toml ./rust/chatbot-server/

WORKDIR /build/rust
RUN cargo fetch

COPY rust /build/rust
RUN if [ "${RUST_BUILD_PROFILE}" = "debug" ]; then \
        cargo build -p chatbot-server; \
    else \
        cargo build --profile "${RUST_BUILD_PROFILE}" -p chatbot-server; \
    fi

# Test image adds pytest (kept out of production)
FROM runtime AS test
RUN pip install --no-cache-dir pytest
WORKDIR /app

# Production image with Gunicorn entrypoint
FROM runtime AS prod
ARG RUST_BUILD_PROFILE=debug
ENV RUST_BUILD_PROFILE=${RUST_BUILD_PROFILE}
COPY --from=rust-build /build/rust/target/${RUST_BUILD_PROFILE}/chatbot-server /usr/local/bin/chatbot-server

# Default to Axum server; bind address is configurable via CHATBOT_BIND_ADDR (see docker-compose)
CMD ["chatbot-server"]
