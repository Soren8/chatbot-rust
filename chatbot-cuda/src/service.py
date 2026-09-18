"""Owned Kokoro TTS / Parakeet STT inference.

One ``InferenceService`` per process, built in FastAPI lifespan from
``VoiceSettings`` and shared by all routes via ``app.state``. ``load_models``
loads Kokoro only for ``tts_provider == "kokoro"`` and always loads STT;
load failures raise (only Kokoro warmup and ``torch.compile`` warn and
continue). Streaming uses a daemon thread feeding an unbounded asyncio queue:
no backpressure, no disconnect cancellation, no shutdown join.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any, AsyncGenerator, Callable, Optional

from .settings import VoiceSettings

logger = logging.getLogger(__name__)

PcmConverter = Callable[[Any], bytes]
KokoroFactory = Callable[[str], Any]
SttFactory = Callable[[str], Any]


def default_pcm_converter(audio: Any) -> bytes:
    """Historical ``float32 -> int16`` conversion (requires numpy/torch)."""
    import numpy as np  # type: ignore

    if hasattr(audio, "numpy"):  # torch.Tensor
        audio = audio.cpu().numpy()
    clipped = np.clip(audio, -1.0, 1.0)
    return (clipped * 32767).astype(np.int16).tobytes()


class InferenceService:
    """Concrete owner of loaded pipelines and readiness state."""

    def __init__(
        self,
        settings: VoiceSettings,
        *,
        kokoro_factory: Optional[KokoroFactory] = None,
        stt_factory: Optional[SttFactory] = None,
        pcm_converter: Optional[PcmConverter] = None,
    ) -> None:
        self.settings = settings
        self._kokoro_pipeline: Any = None
        self._stt_model: Any = None
        self._kokoro_loaded = False
        self._stt_loaded = False
        self._kokoro_factory = kokoro_factory
        self._stt_factory = stt_factory
        self._pcm_converter: PcmConverter = pcm_converter or default_pcm_converter

    # ── Explicit readiness ────────────────────────────────────────────────

    @property
    def kokoro_loaded(self) -> bool:
        return self._kokoro_loaded

    @property
    def stt_loaded(self) -> bool:
        return self._stt_loaded

    def readiness(self) -> dict:
        """Explicit readiness snapshot for ``GET /health``.

        Kokoro is required only when the configured provider is ``"kokoro"``;
        STT is always required. Callers must read this instead of private
        module flags.
        """
        kokoro_required = self.settings.tts_provider == "kokoro"
        ready = (not kokoro_required or self._kokoro_loaded) and self._stt_loaded
        return {
            "status": "ok" if ready else "starting",
            "kokoro_loaded": self._kokoro_loaded,
            "stt_loaded": self._stt_loaded,
        }

    def kokoro_sample_rate(self) -> int:
        return self.settings.kokoro_sample_rate

    # ── Loading ───────────────────────────────────────────────────────────

    def load_stt(self) -> None:
        if self._stt_factory is not None:
            # CPU test seam: injected collaborator replaces the NeMo/CUDA
            # path entirely; no GPU behavior is claimed for this branch.
            self._stt_model = self._stt_factory(self.settings.stt_model_id)
            self._stt_loaded = True
            logger.info("STT model loaded.")
            return

        import torch  # type: ignore

        import nemo.collections.asr as nemo_asr  # type: ignore

        logger.info("Loading STT model %s", self.settings.stt_model_id)
        model = nemo_asr.models.ASRModel.from_pretrained(self.settings.stt_model_id)
        if torch.cuda.is_available():
            model = model.cuda().half()
        # Disable CUDA graphs to avoid cu_call unpacking incompatibility
        # between NeMo and the installed CUDA toolkit version.
        if hasattr(model, "decoding") and hasattr(model.decoding, "decoding"):
            dc = model.decoding.decoding
            if hasattr(dc, "decoding_computer") and hasattr(
                dc.decoding_computer, "cuda_graphs_mode"
            ):
                dc.decoding_computer.cuda_graphs_mode = None
                logger.info("Disabled CUDA graphs for STT decoding.")
        model.eval()
        try:
            model = torch.compile(
                model, fullgraph=False, mode="default", dynamic=True
            )
            logger.info("STT model compiled with torch.compile")
        except Exception as exc:
            logger.warning("torch.compile failed for STT (non-fatal): %s", exc)
        self._stt_model = model
        self._stt_loaded = True
        if torch.cuda.is_available():
            logger.info(
                "STT loaded. VRAM: %.1f GB allocated",
                torch.cuda.memory_allocated() / 1e9,
            )
        logger.info("STT model loaded.")

    def load_kokoro(self) -> None:
        if self._kokoro_factory is not None:
            # CPU test seam: fake pipeline replaces KPipeline/JIT/phonemizer.
            self._kokoro_pipeline = self._kokoro_factory(self.settings.device)
            try:
                for _, _, _ in self._kokoro_pipeline(
                    "Hello, this is a warmup sentence.", voice="af_heart"
                ):
                    break
            except Exception as exc:
                logger.warning("Kokoro warmup failed (non-fatal): %s", exc)
            self._kokoro_loaded = True
            logger.info("Kokoro TTS loaded.")
            return

        import torch  # type: ignore

        from kokoro import KPipeline  # type: ignore

        logger.info("Loading Kokoro TTS pipeline on %s", self.settings.device)
        self._kokoro_pipeline = KPipeline(lang_code="a", device=self.settings.device)

        # Warmup: triggers JIT compilation and phonemizer init before first real request.
        try:
            for _, _, _ in self._kokoro_pipeline(
                "Hello, this is a warmup sentence.", voice="af_heart"
            ):
                break
        except Exception as exc:
            logger.warning("Kokoro warmup failed (non-fatal): %s", exc)

        self._kokoro_loaded = True
        if torch.cuda.is_available():
            logger.info(
                "Kokoro loaded. VRAM: %.1f GB allocated",
                torch.cuda.memory_allocated() / 1e9,
            )
        logger.info("Kokoro TTS loaded.")

    def load_models(self) -> None:
        """Load the configured models; failures propagate to the caller."""
        if self.settings.tts_provider == "kokoro":
            self.load_kokoro()
        self.load_stt()
        try:
            import torch  # type: ignore
        except ImportError:
            return  # CPU test seam: no torch, no VRAM accounting.
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
            logger.info(
                "VRAM after load: %.1f GB allocated, %.1f GB reserved",
                torch.cuda.memory_allocated() / 1e9,
                torch.cuda.memory_reserved() / 1e9,
            )

    # ── Inference ─────────────────────────────────────────────────────────

    def synthesize_kokoro(
        self,
        text: str,
        voice: str = "af_heart",
    ) -> tuple[bytes, int]:
        """Synthesize full-utterance PCM bytes plus sample rate."""
        if not self._kokoro_loaded:
            raise RuntimeError("Kokoro TTS not loaded")

        chunks = []
        for _, _, audio in self._kokoro_pipeline(text, voice=voice):
            chunks.append(self._pcm_converter(audio))
        return b"".join(chunks), self.settings.kokoro_sample_rate

    async def synthesize_kokoro_stream(
        self,
        text: str,
        voice: str = "af_heart",
    ) -> AsyncGenerator[bytes, None]:
        """Yield PCM chunks sentence by sentence as Kokoro produces them.

        A background thread runs the Kokoro generator (which blocks on GPU
        inference per sentence) and posts each chunk to an asyncio queue so
        the event loop stays responsive between sentences.

        Unresolved: unbounded queue, no consumer-cancellation ownership, no
        shutdown join. Preserved as-is in this batch.
        """
        if not self._kokoro_loaded:
            raise RuntimeError("Kokoro TTS not loaded")

        loop = asyncio.get_event_loop()
        queue: asyncio.Queue = asyncio.Queue()

        def _generate() -> None:
            try:
                for _, _, audio in self._kokoro_pipeline(text, voice=voice):
                    chunk = self._pcm_converter(audio)
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

    def transcribe(self, audio_path: str) -> str:
        """Transcribe a WAV file (16 kHz mono) and return the text."""
        if not self._stt_loaded:
            raise RuntimeError("STT model not loaded")

        results = self._stt_model.transcribe([audio_path])
        if not results:
            return ""
        hyp = results[0]
        if isinstance(hyp, str):
            return hyp.strip()
        # NeMo returns Hypothesis objects with a .text attribute
        if hasattr(hyp, "text"):
            return hyp.text.strip()
        return str(hyp).strip()
