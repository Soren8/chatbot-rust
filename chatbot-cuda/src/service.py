"""Owned Kokoro TTS / Parakeet STT inference.

One ``InferenceService`` per process, built in FastAPI lifespan from
``VoiceSettings`` and shared by all routes via ``app.state``. ``load_models``
loads Kokoro only for ``tts_provider == "kokoro"`` and always loads STT;
load failures raise (only Kokoro warmup and ``torch.compile`` warn and
continue). Streaming lifecycle: each ``synthesize_kokoro_stream`` registers
service-owned producer work (daemon thread + bounded asyncio queue,
``STREAM_BUFFER_SIZE``) in ``_active`` under ``_lock``. The producer posts one
``run_coroutine_threadsafe`` put future per item (bytes, error, or sentinel;
never resubmitted, never evicted) and polls it with cancellation. The consumer
only signals ``cancel`` and never unregisters; the producer unregisters after
exit. Production non-streaming work (``synthesize_kokoro_async``,
``transcribe_async``) admits one daemon worker per call in ``_jobs``. Waiter
cancellation only abandons the future; the running call always continues to
exit, and the STT file is removed by that worker before the result settles.
Lifespan teardown ``aclose`` joins streams and jobs off the event loop under
one total ``_SHUTDOWN_JOIN_TIMEOUT`` deadline, warning about and retaining
still-alive workers.

Cooperative boundary (honest): in-flight GPU inference cannot be forcibly
stopped. Admission and shutdown are serialized on the service event loop
(same scope as streaming); ``_lock`` guards flags/sets only, never I/O,
waits, or joins. Loop posts tolerate a closed loop.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import os
import threading
import time
from typing import Any, AsyncGenerator, Callable, Optional

from .settings import VoiceSettings

logger = logging.getLogger(__name__)

PcmConverter = Callable[[Any], bytes]
KokoroFactory = Callable[[str], Any]
SttFactory = Callable[[str], Any]

STREAM_BUFFER_SIZE = 4
_OFFER_POLL_TIMEOUT = 0.02
_GET_POLL_TIMEOUT = 0.05
_SHUTDOWN_JOIN_TIMEOUT = 5.0


def default_pcm_converter(audio: Any) -> bytes:
    """Historical ``float32 -> int16`` conversion (requires numpy/torch)."""
    import numpy as np  # type: ignore

    if hasattr(audio, "numpy"):  # torch.Tensor
        audio = audio.cpu().numpy()
    clipped = np.clip(audio, -1.0, 1.0)
    return (clipped * 32767).astype(np.int16).tobytes()


class _ActiveStream:
    """Small concrete owner for one streaming producer thread."""

    __slots__ = ("queue", "cancel", "loop", "thread", "done")

    def __init__(
        self,
        queue: asyncio.Queue,
        cancel: threading.Event,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        self.queue = queue
        self.cancel = cancel
        self.loop = loop
        self.thread: threading.Thread | None = None
        self.done = threading.Event()


class _ActiveJob:
    """Owner for one non-streaming worker thread (no cancel flag).

    Waiter cancellation abandons the future; the running call always
    continues to exit, so there is nothing to signal.
    """

    __slots__ = ("loop", "thread")

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self.loop = loop
        self.thread: threading.Thread | None = None


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
        self._lock = threading.Lock()
        self._active: set[_ActiveStream] = set()
        self._jobs: set[_ActiveJob] = set()
        self._shutting_down = False

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

    async def synthesize_kokoro_async(
        self,
        text: str,
        voice: str = "af_heart",
    ) -> tuple[bytes, int]:
        """Tracked full synthesis; rejects new work after shutdown."""
        return await self._run_blocking_job(
            self.synthesize_kokoro,
            text,
            voice=voice,
            job_kind="Kokoro synthesis",
        )

    async def synthesize_kokoro_stream(
        self,
        text: str,
        voice: str = "af_heart",
    ) -> AsyncGenerator[bytes, None]:
        """Yield PCM chunks sentence by sentence as Kokoro produces them.

        A service-owned daemon thread runs the Kokoro generator (which blocks
        on GPU inference per sentence) and posts each chunk to a bounded
        asyncio queue (``STREAM_BUFFER_SIZE``), so a slow consumer applies
        backpressure instead of growing memory without bound. Bytes, errors,
        and the end sentinel share one offer path with no eviction, preserving
        order. Closing the generator (disconnect, task cancel, ``aclose``) or
        service ``aclose`` signals the producer, which stops at the next
        sentence boundary; an in-flight pipeline ``next()`` cannot be forcibly
        stopped. A short ``wait_for`` on each ``queue.get`` lets the consumer
        notice cancellation without needing a sentinel.
        """
        if not self._kokoro_loaded:
            raise RuntimeError("Kokoro TTS not loaded")

        loop = asyncio.get_running_loop()
        with self._lock:
            if self._shutting_down:
                raise RuntimeError("Kokoro streaming is shut down")
            queue: asyncio.Queue = asyncio.Queue(maxsize=STREAM_BUFFER_SIZE)
            stream = _ActiveStream(queue, threading.Event(), loop)
            stream.thread = threading.Thread(
                target=self._run_stream,
                args=(stream, text, voice),
                daemon=True,
                name="kokoro-stream",
            )
            self._active.add(stream)
        try:
            stream.thread.start()
        except Exception:
            with self._lock:
                self._active.discard(stream)
            raise

        try:
            while True:
                try:
                    item = await asyncio.wait_for(
                        queue.get(), timeout=_GET_POLL_TIMEOUT
                    )
                except TimeoutError:
                    if stream.cancel.is_set():
                        return
                    continue
                if item is None:
                    break
                if isinstance(item, Exception):
                    raise item
                yield item
        except (GeneratorExit, asyncio.CancelledError):
            stream.cancel.set()
            raise
        finally:
            stream.cancel.set()

    def active_stream_count(self) -> int:
        """Number of registered in-flight streaming producers."""
        with self._lock:
            return len(self._active)

    def active_job_count(self) -> int:
        """Number of registered in-flight non-streaming workers."""
        with self._lock:
            return len(self._jobs)

    async def aclose(self) -> None:
        """Mark shutdown, then join streams and jobs off the loop.

        New streams and jobs are rejected. Still-alive workers are logged
        and stay tracked until they exit. The lock is never held across
        waits or joins.
        """
        with self._lock:
            self._shutting_down = True
            streams = list(self._active)
            jobs = list(self._jobs)
        for stream in streams:
            stream.cancel.set()
        if streams or jobs:
            await asyncio.to_thread(self._join_all, streams, jobs)

    @staticmethod
    def _join_all(
        streams: list[_ActiveStream], jobs: list[_ActiveJob]
    ) -> None:
        deadline = time.monotonic() + _SHUTDOWN_JOIN_TIMEOUT
        for stream in streams:
            if time.monotonic() >= deadline:
                break
            thread = stream.thread
            if thread is not None:
                thread.join(timeout=max(0.0, deadline - time.monotonic()))
        for job in jobs:
            if time.monotonic() >= deadline:
                break
            thread = job.thread
            if thread is not None:
                thread.join(timeout=max(0.0, deadline - time.monotonic()))
        alive = [
            work
            for work in (*streams, *jobs)
            if work.thread is not None and work.thread.is_alive()
        ]
        if alive:
            logger.warning(
                "Shutdown timed out with %d worker(s) still "
                "running; they stay tracked until exit",
                len(alive),
            )

    async def _run_blocking_job(
        self,
        func: Callable[..., Any],
        *args: Any,
        job_kind: str = "inference",
        cleanup_path: Optional[str] = None,
        **kwargs: Any,
    ) -> Any:
        """Admit one worker and await its future.

        Waiter cancellation abandons the future; the worker always runs to
        exit and settles the result only after file cleanup and
        unregistration. ``cleanup_path`` is removed on every path after
        this call, so callers never unlink. No lock is held during I/O.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            if cleanup_path is not None:
                self._unlink_quietly(cleanup_path)
            raise
        job = _ActiveJob(loop)
        future = loop.create_future()
        try:
            job.thread = threading.Thread(
                target=self._run_job,
                args=(job, future, func, args, kwargs, cleanup_path),
                daemon=True,
                name="inference-job",
            )
        except Exception:
            if not future.done():
                future.cancel()
            if cleanup_path is not None:
                self._unlink_quietly(cleanup_path)
            raise
        with self._lock:
            if self._shutting_down:
                rejected = True
            else:
                self._jobs.add(job)
                rejected = False
        if rejected:
            if not future.done():
                future.cancel()
            if cleanup_path is not None:
                self._unlink_quietly(cleanup_path)
            raise RuntimeError(f"{job_kind} is shut down")
        try:
            job.thread.start()
        except Exception:
            with self._lock:
                self._jobs.discard(job)
            if not future.done():
                future.cancel()
            if cleanup_path is not None:
                self._unlink_quietly(cleanup_path)
            raise
        return await future

    def _run_job(
        self,
        job: _ActiveJob,
        future: asyncio.Future,
        func: Callable[..., Any],
        args: tuple,
        kwargs: dict,
        cleanup_path: Optional[str],
    ) -> None:
        """Run, clean up, unregister, then settle; never raises."""
        try:
            outcome = func(*args, **kwargs)
        except Exception as exc:
            outcome = exc
            is_error = True
        else:
            is_error = False
        if cleanup_path is not None:
            self._unlink_quietly(cleanup_path)
        with self._lock:
            self._jobs.discard(job)
        if is_error:
            self._deliver_job_result(job, future, None, outcome)
        else:
            self._deliver_job_result(job, future, outcome, None)

    def _deliver_job_result(
        self,
        job: _ActiveJob,
        future: asyncio.Future,
        result: Any,
        exc: Optional[BaseException],
    ) -> None:
        """Post one result to the loop; never raises or double-settles."""
        loop = job.loop
        if loop.is_closed():
            return

        def _set() -> None:
            if future.done():
                return
            if exc is not None:
                future.set_exception(exc)
            else:
                future.set_result(result)

        try:
            loop.call_soon_threadsafe(_set)
        except RuntimeError:
            pass

    @staticmethod
    def _unlink_quietly(path: str) -> None:
        try:
            os.unlink(path)
        except Exception:
            pass

    def _run_stream(self, stream: _ActiveStream, text: str, voice: str) -> None:
        """Producer body: sentences become PCM on the bounded queue.

        Never raises: pipeline/converter failures are offered as the terminal
        queue item so the consumer sees them in order. Cancel is checked
        before and after each pipeline ``next()``; cancelled output is never
        converted. Always closes the iterator if supported, sets ``done``,
        and unregisters, even when the loop is already closed.
        """
        iterator = None
        try:
            try:
                iterator = iter(self._kokoro_pipeline(text, voice=voice))
            except Exception as exc:
                self._offer(stream, exc)
            else:
                while True:
                    if stream.cancel.is_set():
                        break
                    try:
                        _, _, audio = next(iterator)
                    except StopIteration:
                        self._offer(stream, None)
                        break
                    except Exception as exc:
                        self._offer(stream, exc)
                        break
                    if stream.cancel.is_set():
                        break
                    try:
                        chunk = self._pcm_converter(audio)
                    except Exception as exc:
                        self._offer(stream, exc)
                        break
                    if not self._offer(stream, chunk):
                        break
        finally:
            if iterator is not None:
                close = getattr(iterator, "close", None)
                if close is not None:
                    try:
                        close()
                    except Exception:
                        pass
            stream.done.set()
            with self._lock:
                self._active.discard(stream)

    def _offer(self, stream: _ActiveStream, item: object) -> bool:
        """Offer one queue item via a single put future; never resubmits.

        Waits on the same future, polling for cancel/closed loop, then cancels
        that future and reports False. Never raises.
        """
        loop = stream.loop
        if loop.is_closed():
            return False
        coro = stream.queue.put(item)
        try:
            future = asyncio.run_coroutine_threadsafe(coro, loop)
        except RuntimeError:
            coro.close()
            return False
        while True:
            try:
                future.result(timeout=_OFFER_POLL_TIMEOUT)
                return True
            except concurrent.futures.TimeoutError:
                if stream.cancel.is_set() or loop.is_closed():
                    future.cancel()
                    return False
            except Exception:
                return False

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

    async def transcribe_async(self, audio_path: str) -> str:
        """Tracked transcription; owns the staging file until settle."""
        return await self._run_blocking_job(
            self.transcribe,
            audio_path,
            job_kind="STT transcription",
            cleanup_path=audio_path,
        )
