"""Voice-service settings resolved once at startup.

Raw ``.config.yml`` read with no ``${VAR}`` substitution (the Rust webserver
expands; Python keeps values verbatim). ``tts_provider`` lowercases to
``"kokoro"`` by default; ``STT_MODEL_ID`` env defaults to
``nvidia/parakeet-tdt-0.6b-v2``; ``device`` is ``cuda:{CUDA_VISIBLE_DEVICES}``
(verbatim) when CUDA is available, else ``cuda:0`` or ``cpu``. Sample rates:
Kokoro 24000, Parakeet 16000. No torch/numpy/FastAPI imports.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, Mapping, Optional

DEFAULT_CONFIG_PATH = "/app/.config.yml"
DEFAULT_TTS_PROVIDER = "kokoro"
DEFAULT_STT_MODEL_ID = "nvidia/parakeet-tdt-0.6b-v2"
KOKORO_SAMPLE_RATE = 24000
PARAKEET_SAMPLE_RATE = 16000


def _load_yaml_mapping(config_path: str) -> dict:
    """Load the raw YAML mapping, returning {} on any failure.

    Preserves the historical ``except Exception: return default`` behavior:
    missing file, missing ``yaml`` package, or unparsable content all fall
    back to defaults. No ``${VAR}`` substitution is performed (unlike Rust).
    """
    try:
        import yaml  # type: ignore
    except Exception:
        return {}
    try:
        with open(config_path) as f:
            cfg = yaml.safe_load(f) or {}
        if isinstance(cfg, dict):
            return cfg
        return {}
    except Exception:
        return {}


def read_tts_provider(config_path: str = DEFAULT_CONFIG_PATH) -> str:
    """Read the raw ``tts_provider`` value, lowercased, default ``"kokoro"``."""
    cfg = _load_yaml_mapping(config_path)
    try:
        return str(cfg.get("tts_provider", DEFAULT_TTS_PROVIDER)).lower()
    except Exception:
        return DEFAULT_TTS_PROVIDER


def _default_cuda_available() -> bool:
    """CUDA probe without importing torch at module load.

    False when torch is not installed (CPU test seam); any other probe
    failure propagates instead of silently resolving to ``"cpu"``.
    """
    try:
        import torch  # type: ignore
    except ImportError:
        return False
    return bool(torch.cuda.is_available())


def resolve_device(
    env: Optional[Mapping[str, str]] = None,
    cuda_available: Optional[Callable[[], bool]] = None,
) -> str:
    """Resolve the inference device string, preserving historical semantics.

    Given CUDA availability and the environment, when CUDA is available and
    ``CUDA_VISIBLE_DEVICES`` is present then the device is
    ``f"cuda:{CUDA_VISIBLE_DEVICES}"`` (value verbatim); when CUDA is
    available without the variable then ``"cuda:0"``; otherwise ``"cpu"``.
    """
    mapping: Mapping[str, str] = env if env is not None else os.environ
    available = cuda_available() if cuda_available is not None else _default_cuda_available()
    if available and "CUDA_VISIBLE_DEVICES" in mapping:
        return f"cuda:{mapping['CUDA_VISIBLE_DEVICES']}"
    return "cuda:0" if available else "cpu"


@dataclass(frozen=True)
class VoiceSettings:
    """One explicitly resolved settings value per voice-service process."""

    device: str
    stt_model_id: str
    tts_provider: str
    kokoro_sample_rate: int = KOKORO_SAMPLE_RATE
    parakeet_sample_rate: int = PARAKEET_SAMPLE_RATE


def resolve_settings(
    env: Optional[Mapping[str, str]] = None,
    config_path: str = DEFAULT_CONFIG_PATH,
    cuda_available: Optional[Callable[[], bool]] = None,
) -> VoiceSettings:
    """Resolve settings explicitly at startup (no import-time side effects).

    ``env`` defaults to ``os.environ``; ``cuda_available`` defaults to a
    guarded torch probe. ``config_path`` defaults to ``/app/.config.yml`` to
    preserve the historical hardcoded path.
    """
    mapping: Mapping[str, str] = env if env is not None else os.environ
    tts_provider = read_tts_provider(config_path)
    stt_model_id = str(mapping.get("STT_MODEL_ID", DEFAULT_STT_MODEL_ID))
    device = resolve_device(mapping, cuda_available)
    return VoiceSettings(
        device=device,
        stt_model_id=stt_model_id,
        tts_provider=tts_provider,
    )
