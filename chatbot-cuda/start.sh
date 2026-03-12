#!/usr/bin/env bash
# Startup script for the voice service.
# Downloads models to the persistent cache volume on first run,
# then launches uvicorn.  Subsequent starts skip downloading entirely.
set -euo pipefail

TTS_MODEL="${TTS_MODEL_ID:-Qwen/Qwen3-TTS-12Hz-1.7B-CustomVoice}"
STT_MODEL="${STT_MODEL_ID:-nvidia/parakeet-tdt-0.6b-v2}"

echo "[start] ensuring TTS model cached: ${TTS_MODEL}"
python3 - <<PYEOF
import os
from huggingface_hub import snapshot_download
snapshot_download("${TTS_MODEL}", cache_dir=os.environ.get("HF_HOME", "/app/model_cache"))
print("[start] TTS model cache ready.", flush=True)
PYEOF

echo "[start] ensuring STT model cached: ${STT_MODEL}"
python3 - <<PYEOF
import os, nemo.collections.asr as nemo_asr
# from_pretrained downloads to NEMO_CACHE_DIR on cache miss; no-op on hit
model = nemo_asr.models.ASRModel.from_pretrained("${STT_MODEL}")
del model   # free memory before uvicorn takes over
print("[start] STT model cache ready.", flush=True)
PYEOF

echo "[start] starting uvicorn"
exec uvicorn src.main:app --host 0.0.0.0 --port 5100
