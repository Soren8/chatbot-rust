# syntax=docker/dockerfile:1.7

FROM nvidia/cuda:12.4.1-cudnn-runtime-ubuntu22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
# Cython/packaging tools often needed for compiling some audio extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-pip \
    python3-venv \
    python3-dev \
    git \
    ffmpeg \
    libsndfile1 \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

WORKDIR /app

ENV VIRTUAL_ENV=/app/.venv
RUN uv venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

COPY pyproject.toml .

# Install dependencies with caching
# We mount the cache to /root/.cache/uv to speed up re-builds
# Note: NeMo is heavy, so we mount the uv cache
RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip install -r pyproject.toml

COPY src ./src

# Create cache directories
RUN mkdir -p /app/data/models /app/data/cache && chmod -R 777 /app/data

ENV MODELS_CACHE_DIR=/app/data/cache
ENV HF_HOME=/app/data/cache/huggingface

EXPOSE 8000

CMD ["python3", "src/main.py"]
