#!/usr/bin/env bash
# Startup script for the voice service.
# Downloads models to the persistent cache volume on first run,
# then launches uvicorn.  Subsequent starts skip downloading entirely.
set -euo pipefail

QWEN_MODEL_ID="${TTS_MODEL_ID:-Qwen/Qwen3-TTS-12Hz-1.7B-CustomVoice}"
STT_MODEL="${STT_MODEL_ID:-nvidia/parakeet-tdt-0.6b-v2}"

# Read tts_provider and voice_gpu_device from .config.yml (same source of truth as the Rust webserver).
_cfg=$(python3 - <<'PYEOF'
import sys
try:
    import yaml
    with open("/app/.config.yml") as f:
        cfg = yaml.safe_load(f) or {}
    provider = cfg.get("tts_provider", "qwen").lower()
    gpu = str(cfg.get("voice_gpu_device", 0))
except Exception as e:
    print(f"Error reading config: {e}", file=sys.stderr)
    provider = "qwen"
    gpu = "0"
print(f"{provider} {gpu}")
PYEOF
)
TTS_PROVIDER=$(echo "$_cfg" | cut -d' ' -f1)
export CUDA_VISIBLE_DEVICES=$(echo "$_cfg" | cut -d' ' -f2)

echo "[start] tts_provider=${TTS_PROVIDER}"
echo "[start] CUDA_VISIBLE_DEVICES=${CUDA_VISIBLE_DEVICES}"

if [ "$TTS_PROVIDER" = "kokoro" ]; then
    echo "[start] ensuring Kokoro TTS model cached"
    python3 - <<'PYEOF'
import os
from huggingface_hub import snapshot_download
snapshot_download("hexgrad/Kokoro-82M", cache_dir=os.environ.get("HF_HOME", "/app/model_cache"))
print("[start] Kokoro model cache ready.", flush=True)
PYEOF
else
    echo "[start] ensuring Qwen TTS model cached: ${QWEN_MODEL_ID}"
    python3 - <<PYEOF
import os
from huggingface_hub import snapshot_download
snapshot_download("${QWEN_MODEL_ID}", cache_dir=os.environ.get("HF_HOME", "/app/model_cache"))
print("[start] TTS model cache ready.", flush=True)
PYEOF
fi

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
