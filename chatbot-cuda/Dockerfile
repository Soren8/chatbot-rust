FROM pytorch/pytorch:2.11.0-cuda12.8-cudnn9-runtime@sha256:eee11b3b3872a8c838e35ef48f08b2d5def2080902c7f666831310ca1a0ef2be

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    HF_HOME=/app/model_cache \
    TORCH_HOME=/app/model_cache \
    NEMO_CACHE_DIR=/app/model_cache/nemo \
    CUDA_DEVICE_ORDER=PCI_BUS_ID

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ffmpeg \
    libsndfile1 \
    sox \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# qwen-tts 0.1.1 declares transformers==4.57.3 (huggingface_hub<1). The package
# needs transformers 5.x for hub 1.x; install it after the resolved pins.
RUN --mount=type=cache,target=/root/.cache/pip \
    grep -v '^qwen-tts==' requirements.txt > /tmp/requirements.pip.txt && \
    python3 -m pip install --break-system-packages -r /tmp/requirements.pip.txt && \
    python3 -m pip install --break-system-packages --no-deps "$(grep '^qwen-tts==' requirements.txt)"

# misaki[en] (Kokoro's G2P engine) requires spaCy's en_core_web_sm model.
# Bake it into the image so it's available offline at runtime.
RUN --mount=type=cache,target=/root/.cache/pip \
    python3 -m pip install --break-system-packages \
    https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl

COPY src/ ./src/
COPY start.sh .
RUN chmod +x start.sh

EXPOSE 5100

# Models are downloaded to /app/model_cache (host-mounted volume) at first startup.
# Subsequent starts skip downloading entirely.
CMD ["./start.sh"]
