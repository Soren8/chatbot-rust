"""Model loading and inference for Qwen3-TTS, Kokoro-TTS and Parakeet STT."""

import asyncio
import base64
import io
import logging
import os
import tempfile
import threading
from typing import Optional, AsyncGenerator

import numpy as np
import torch

logger = logging.getLogger(__name__)

# ── Model globals ────────────────────────────────────────────────────────────

_tts_model = None
_tts_loaded: bool = False
_tts_sample_rate: int = 24000

_kokoro_pipeline = None
_kokoro_loaded: bool = False
_KOKORO_SR: int = 24000

_stt_model = None
_stt_loaded: bool = False

_DEVICE = "cuda:0" if torch.cuda.is_available() else "cpu"
_TTS_MODEL_ID = os.environ.get("TTS_MODEL_ID", "Qwen/Qwen3-TTS-12Hz-1.7B-CustomVoice")
_STT_MODEL_ID = os.environ.get("STT_MODEL_ID", "nvidia/parakeet-tdt-0.6b-v2")


def _read_tts_provider() -> str:
    """Read tts_provider from .config.yml, same source of truth as the Rust webserver."""
    try:
        import yaml
        with open("/app/.config.yml") as f:
            cfg = yaml.safe_load(f) or {}
        return str(cfg.get("tts_provider", "qwen")).lower()
    except Exception:
        return "qwen"


_TTS_MODEL = _read_tts_provider()

_GEN_KWARGS = dict(
    max_new_tokens=2048,
    do_sample=True,
    top_k=50,
    top_p=1.0,
    temperature=0.9,
    repetition_penalty=1.05,
)

# ── Loading ──────────────────────────────────────────────────────────────────

def load_tts() -> None:
    global _tts_model, _tts_loaded, _tts_sample_rate
    from qwen_tts import Qwen3TTSModel

    logger.info("Loading TTS model %s on %s", _TTS_MODEL_ID, _DEVICE)

    # Try Flash Attention 2 first for maximum throughput; fall back if unsupported.
    try:
        _tts_model = Qwen3TTSModel.from_pretrained(
            _TTS_MODEL_ID,
            device_map=_DEVICE,
            dtype=torch.bfloat16,
            attn_implementation="flash_attention_2",
        )
        logger.info("TTS loaded with Flash Attention 2")
    except (TypeError, ValueError, ImportError) as exc:
        logger.warning("Flash Attention 2 unavailable for TTS (%s), using default attention", exc)
        _tts_model = Qwen3TTSModel.from_pretrained(
            _TTS_MODEL_ID,
            device_map=_DEVICE,
            dtype=torch.bfloat16,
        )

    # torch.compile speeds up per-token generation via kernel fusion.
    # fullgraph=False tolerates Python control flow; mode=default avoids
    # CUDA-graph shape restrictions that would break dynamic-length generation.
    try:
        _tts_model = torch.compile(_tts_model, fullgraph=False, mode="default")
        logger.info("TTS model compiled with torch.compile")
    except Exception as exc:
        logger.warning("torch.compile failed (non-fatal): %s", exc)

    # Warmup: run a realistic sentence to trigger lazy JIT compilation
    # on all code paths before the first real request arrives.
    try:
        _tts_model.generate_custom_voice(
            text="Hello, this is a warmup sentence for the text-to-speech system.",
            language="English",
            speaker="Ryan",
            **_GEN_KWARGS,
        )
    except Exception as exc:
        logger.warning("TTS warmup failed (non-fatal): %s", exc)

    _tts_loaded = True
    logger.info("TTS model loaded.")


def load_stt() -> None:
    global _stt_model, _stt_loaded
    import nemo.collections.asr as nemo_asr

    logger.info("Loading STT model %s", _STT_MODEL_ID)
    _stt_model = nemo_asr.models.ASRModel.from_pretrained(_STT_MODEL_ID)
    if torch.cuda.is_available():
        _stt_model = _stt_model.cuda()
    # Disable CUDA graphs to avoid cu_call unpacking incompatibility
    # between NeMo and the installed CUDA toolkit version.
    if hasattr(_stt_model, 'decoding') and hasattr(_stt_model.decoding, 'decoding'):
        dc = _stt_model.decoding.decoding
        if hasattr(dc, 'decoding_computer') and hasattr(dc.decoding_computer, 'cuda_graphs_mode'):
            dc.decoding_computer.cuda_graphs_mode = None
            logger.info("Disabled CUDA graphs for STT decoding.")
    _stt_model.eval()
    _stt_loaded = True
    logger.info("STT model loaded.")


def load_kokoro() -> None:
    global _kokoro_pipeline, _kokoro_loaded
    from kokoro import KPipeline

    logger.info("Loading Kokoro TTS pipeline on %s", _DEVICE)
    _kokoro_pipeline = KPipeline(lang_code="a", device=_DEVICE)

    # Warmup: trigger any lazy JIT / phonemizer init before first real request.
    try:
        for _, _, _ in _kokoro_pipeline(
            "Hello, this is a warmup sentence.", voice="af_heart"
        ):
            break
    except Exception as exc:
        logger.warning("Kokoro warmup failed (non-fatal): %s", exc)

    _kokoro_loaded = True
    logger.info("Kokoro TTS loaded.")


def load_models() -> None:
    if _TTS_MODEL == "kokoro":
        load_kokoro()
    else:
        load_tts()
    load_stt()


# ── TTS inference ────────────────────────────────────────────────────────────

def synthesize(
    text: str,
    voice: str = "Ryan",
    ref_audio: Optional[str] = None,
    ref_text: Optional[str] = None,
) -> tuple[bytes, int]:
    """
    Synthesize text to raw 16-bit mono PCM bytes.

    If ref_audio (base64-encoded WAV/WebM) and ref_text are provided, voice
    cloning is attempted using generate_voice_clone(); otherwise the preset
    voice named by `voice` is used with generate_custom_voice().

    Returns (pcm_bytes, sample_rate).
    """
    if not _tts_loaded:
        raise RuntimeError("TTS model not loaded")

    if ref_audio and ref_text:
        audio_bytes = base64.b64decode(ref_audio)
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
            tmp.write(audio_bytes)
            tmp_path = tmp.name
        try:
            wavs, sr = _tts_model.generate_voice_clone(
                text=text,
                language="Auto",
                ref_audio=tmp_path,
                ref_text=ref_text,
                **_GEN_KWARGS,
            )
        finally:
            os.unlink(tmp_path)
    else:
        wavs, sr = _tts_model.generate_custom_voice(
            text=text,
            language="Auto",
            speaker=voice,
            **_GEN_KWARGS,
        )

    audio = wavs[0]  # first (and only) item for single-text requests
    pcm = _float32_to_pcm16(audio)
    return pcm, int(sr)


async def synthesize_stream(
    text: str,
    voice: str = "Ryan",
    ref_audio: Optional[str] = None,
    ref_text: Optional[str] = None,
) -> AsyncGenerator[bytes, None]:
    """
    Yield PCM chunks as they are produced.

    Synthesis is offloaded to a thread so the event loop remains responsive.
    Qwen3-TTS doesn't expose token-level streaming; the full sentence is
    synthesised and then yielded in chunks.
    """
    pcm, _ = await asyncio.to_thread(
        synthesize, text, voice=voice, ref_audio=ref_audio, ref_text=ref_text
    )

    chunk_size = 4096
    for i in range(0, len(pcm), chunk_size):
        yield pcm[i : i + chunk_size]


# ── Kokoro TTS inference ─────────────────────────────────────────────────────

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


# ── STT inference ────────────────────────────────────────────────────────────

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


# ── Helpers ──────────────────────────────────────────────────────────────────

def _float32_to_pcm16(audio) -> bytes:
    if hasattr(audio, "numpy"):  # torch.Tensor
        audio = audio.cpu().numpy()
    clipped = np.clip(audio, -1.0, 1.0)
    return (clipped * 32767).astype(np.int16).tobytes()


def tts_sample_rate() -> int:
    return _tts_sample_rate
