#!/usr/bin/env bash
# Startup script for the voice service.
# Downloads models to the persistent cache volume on first run,
# then launches uvicorn.  Subsequent starts skip downloading entirely.
set -euo pipefail

QWEN_MODEL_ID="${TTS_MODEL_ID:-Qwen/Qwen3-TTS-12Hz-1.7B-CustomVoice}"
STT_MODEL="${STT_MODEL_ID:-nvidia/parakeet-tdt-0.6b-v2}"

# Read tts_provider from .config.yml (same source of truth as the Rust webserver).
TTS_PROVIDER=$(python3 - <<'PYEOF'
import sys
try:
    import yaml
    with open("/app/.config.yml") as f:
        cfg = yaml.safe_load(f) or {}
    print(cfg.get("tts_provider", "qwen").lower())
except Exception as e:
    print("qwen", file=sys.stderr)
    print("qwen")
PYEOF
)

echo "[start] tts_provider=${TTS_PROVIDER}"

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
