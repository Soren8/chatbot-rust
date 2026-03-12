FROM nvidia/cuda:12.6.3-cudnn-runtime-ubuntu24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    HF_HOME=/app/model_cache \
    TORCH_HOME=/app/model_cache \
    NEMO_CACHE_DIR=/app/model_cache/nemo

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.12 \
    python3-pip \
    python3.12-dev \
    ffmpeg \
    libsndfile1 \
    sox \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .

# Install PyTorch for CUDA 12.6 first so NeMo and qwen-tts reuse it
RUN --mount=type=cache,target=/root/.cache/pip \
    pip3 install --break-system-packages \
    torch torchaudio \
    --index-url https://download.pytorch.org/whl/cu126


RUN --mount=type=cache,target=/root/.cache/pip \
    pip3 install --break-system-packages -r requirements.txt

COPY src/ ./src/
COPY start.sh .
RUN chmod +x start.sh

EXPOSE 5100

# Models are downloaded to /app/model_cache (host-mounted volume) at first startup.
# Subsequent starts skip downloading entirely.
CMD ["./start.sh"]
