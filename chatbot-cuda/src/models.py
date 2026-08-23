"""Model loading and inference for Kokoro TTS and Parakeet STT."""

import asyncio
import logging
import os
import threading
from typing import AsyncGenerator

import numpy as np
import torch

logger = logging.getLogger(__name__)

# ── Model globals ────────────────────────────────────────────────────────────

_kokoro_pipeline = None
_kokoro_loaded: bool = False
_KOKORO_SR: int = 24000

_stt_model = None
_stt_loaded: bool = False

_DEVICE = f"cuda:{os.environ['CUDA_VISIBLE_DEVICES']}" if torch.cuda.is_available() and "CUDA_VISIBLE_DEVICES" in os.environ else ("cuda:0" if torch.cuda.is_available() else "cpu")
_STT_MODEL_ID = os.environ.get("STT_MODEL_ID", "nvidia/parakeet-tdt-0.6b-v2")


def _read_tts_provider() -> str:
    """Read tts_provider from .config.yml, same source of truth as the Rust webserver."""
    try:
        import yaml
        with open("/app/.config.yml") as f:
            cfg = yaml.safe_load(f) or {}
        return str(cfg.get("tts_provider", "kokoro")).lower()
    except Exception:
        return "kokoro"


_TTS_MODEL = _read_tts_provider()


def load_stt() -> None:
    global _stt_model, _stt_loaded
    import nemo.collections.asr as nemo_asr

    logger.info("Loading STT model %s", _STT_MODEL_ID)
    _stt_model = nemo_asr.models.ASRModel.from_pretrained(_STT_MODEL_ID)
    if torch.cuda.is_available():
        _stt_model = _stt_model.cuda().half()
    # Disable CUDA graphs to avoid cu_call unpacking incompatibility
    # between NeMo and the installed CUDA toolkit version.
    if hasattr(_stt_model, 'decoding') and hasattr(_stt_model.decoding, 'decoding'):
        dc = _stt_model.decoding.decoding
        if hasattr(dc, 'decoding_computer') and hasattr(dc.decoding_computer, 'cuda_graphs_mode'):
            dc.decoding_computer.cuda_graphs_mode = None
            logger.info("Disabled CUDA graphs for STT decoding.")
    _stt_model.eval()
    try:
        _stt_model = torch.compile(
            _stt_model, fullgraph=False, mode="default", dynamic=True
        )
        logger.info("STT model compiled with torch.compile")
    except Exception as exc:
        logger.warning("torch.compile failed for STT (non-fatal): %s", exc)
    _stt_loaded = True
    if torch.cuda.is_available():
        logger.info("STT loaded. VRAM: %.1f GB allocated", torch.cuda.memory_allocated() / 1e9)
    logger.info("STT model loaded.")


def load_kokoro() -> None:
    global _kokoro_pipeline, _kokoro_loaded
    from kokoro import KPipeline

    logger.info("Loading Kokoro TTS pipeline on %s", _DEVICE)
    _kokoro_pipeline = KPipeline(lang_code="a", device=_DEVICE)

    # Warmup: triggers JIT compilation and phonemizer init before first real request.
    try:
        for _, _, _ in _kokoro_pipeline(
            "Hello, this is a warmup sentence.", voice="af_heart"
        ):
            break
    except Exception as exc:
        logger.warning("Kokoro warmup failed (non-fatal): %s", exc)

    _kokoro_loaded = True
    if torch.cuda.is_available():
        logger.info("Kokoro loaded. VRAM: %.1f GB allocated", torch.cuda.memory_allocated() / 1e9)
    logger.info("Kokoro TTS loaded.")


def load_models() -> None:
    if _TTS_MODEL == "kokoro":
        load_kokoro()
    load_stt()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()
        logger.info("VRAM after load: %.1f GB allocated, %.1f GB reserved",
                    torch.cuda.memory_allocated() / 1e9,
                    torch.cuda.memory_reserved() / 1e9)


def synthesize_kokoro(
    text: str,
    voice: str = "af_heart",
) -> tuple[bytes, int]:
    """
    Synthesize text with Kokoro and return raw 16-bit mono PCM bytes.

    Kokoro chunks by sentence internally; this function concatenates all
    sentence chunks into a single blob for callers that need the full audio.
    Returns (pcm_bytes, sample_rate).
    """
    if not _kokoro_loaded:
        raise RuntimeError("Kokoro TTS not loaded")

    chunks = []
    for _, _, audio in _kokoro_pipeline(text, voice=voice):
        chunks.append(_float32_to_pcm16(audio))
    return b"".join(chunks), _KOKORO_SR


async def synthesize_kokoro_stream(
    text: str,
    voice: str = "af_heart",
) -> AsyncGenerator[bytes, None]:
    """
    Yield PCM chunks sentence by sentence as Kokoro produces them.

    A background thread runs the Kokoro generator (which blocks on GPU
    inference per sentence) and posts each chunk to an asyncio queue so
    the event loop stays responsive between sentences.
    """
    if not _kokoro_loaded:
        raise RuntimeError("Kokoro TTS not loaded")

    loop = asyncio.get_event_loop()
    queue: asyncio.Queue = asyncio.Queue()

    def _generate() -> None:
        try:
            for _, _, audio in _kokoro_pipeline(text, voice=voice):
                chunk = _float32_to_pcm16(audio)
                loop.call_soon_threadsafe(queue.put_nowait, chunk)
        except Exception as exc:
            loop.call_soon_threadsafe(queue.put_nowait, exc)
        finally:
            loop.call_soon_threadsafe(queue.put_nowait, None)  # sentinel

    threading.Thread(target=_generate, daemon=True).start()

    while True:
        item = await queue.get()
        if item is None:
            break
        if isinstance(item, Exception):
            raise item
        yield item


def kokoro_sample_rate() -> int:
    return _KOKORO_SR


def transcribe(audio_path: str) -> str:
    """Transcribe a WAV file (16 kHz mono) and return the text."""
    if not _stt_loaded:
        raise RuntimeError("STT model not loaded")

    results = _stt_model.transcribe([audio_path])
    if not results:
        return ""
    hyp = results[0]
    if isinstance(hyp, str):
        return hyp.strip()
    # NeMo returns Hypothesis objects with a .text attribute
    if hasattr(hyp, 'text'):
        return hyp.text.strip()
    return str(hyp).strip()


def _float32_to_pcm16(audio) -> bytes:
    if hasattr(audio, "numpy"):  # torch.Tensor
        audio = audio.cpu().numpy()
    clipped = np.clip(audio, -1.0, 1.0)
    return (clipped * 32767).astype(np.int16).tobytes()
