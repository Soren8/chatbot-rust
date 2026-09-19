"""FastAPI voice service — TTS (Kokoro) and STT (Parakeet).

``create_app`` builds the app; ``lifespan`` resolves settings, takes the
owned ``InferenceService``, and loads it — including factory-injected test
services, so tests exercise the same startup path and failure. Every route
uses ``request.app.state.inference_service``. Startup load failures propagate
and the app never starts degraded. HTTP shapes: TTS 400/500 with
``application/octet-stream`` + ``X-Sample-Rate``; STT 400/422/500 with WAV
staging owned by the service worker through its actual exit; health reports
the owned service's flags. Streaming uses a service-owned daemon thread per
request with a bounded queue (``STREAM_BUFFER_SIZE`` backpressure): consumer
close/cancel signals the producer at the next sentence boundary, and
lifespan teardown cancels active streams and joins streams and jobs
off the event loop under one deadline, then rejects new work.
In-flight GPU inference for the current sentence or call cannot be
interrupted (cooperative boundary).
"""

import logging
import tempfile
from contextlib import aclosing, asynccontextmanager

from fastapi import APIRouter, FastAPI, File, HTTPException, Request, Response, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from .audio_utils import webm_to_wav_bytes
from .service import InferenceService
from .settings import VoiceSettings, resolve_settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter()


@asynccontextmanager
async def lifespan(app: FastAPI):
    pending_service: InferenceService | None = app.state.pending_service
    pending_settings: VoiceSettings | None = app.state.pending_settings
    if pending_service is not None:
        service = pending_service
        settings = pending_settings or service.settings
    else:
        settings = pending_settings or resolve_settings()
        service = InferenceService(settings)
    service.load_models()
    app.state.voice_settings = settings
    app.state.inference_service = service
    try:
        yield
    finally:
        await service.aclose()


def create_app(
    settings: VoiceSettings | None = None,
    inference_service: InferenceService | None = None,
    audio_converter=None,
) -> FastAPI:
    """Build one voice-service app with lifespan-owned inference state."""
    app = FastAPI(title="Voice Service", lifespan=lifespan)
    app.state.pending_settings = settings
    app.state.pending_service = inference_service
    app.state.audio_converter = audio_converter or webm_to_wav_bytes
    app.include_router(router)
    return app


# ── Health ────────────────────────────────────────────────────────────────────

@router.get("/health")
def health(request: Request):
    service: InferenceService = request.app.state.inference_service
    readiness = service.readiness()
    return {
        "status": "ok",
        "kokoro_loaded": readiness["kokoro_loaded"],
        "stt_loaded": readiness["stt_loaded"],
    }


# ── Kokoro TTS ────────────────────────────────────────────────────────────────

class KokoroTtsRequest(BaseModel):
    text: str
    voice: str = "af_heart"


@router.post("/v1/tts/kokoro")
async def kokoro_tts(req: KokoroTtsRequest, request: Request):
    if not req.text.strip():
        raise HTTPException(status_code=400, detail="text is required")

    service: InferenceService = request.app.state.inference_service
    try:
        pcm, sr = await service.synthesize_kokoro_async(
            text=req.text,
            voice=req.voice,
        )
    except Exception as exc:
        logger.exception("Kokoro TTS synthesis failed")
        raise HTTPException(status_code=500, detail=str(exc))

    return Response(
        content=pcm,
        media_type="application/octet-stream",
        headers={"X-Sample-Rate": str(sr)},
    )


@router.post("/v1/tts/kokoro/stream")
async def kokoro_tts_stream(req: KokoroTtsRequest, request: Request):
    if not req.text.strip():
        raise HTTPException(status_code=400, detail="text is required")

    service: InferenceService = request.app.state.inference_service

    async def generator():
        try:
            async with aclosing(
                service.synthesize_kokoro_stream(
                    text=req.text,
                    voice=req.voice,
                )
            ) as stream:
                async for chunk in stream:
                    yield chunk
        except Exception as exc:
            logger.exception("Kokoro TTS stream failed")
            raise HTTPException(status_code=500, detail=str(exc))

    sr = service.kokoro_sample_rate()
    return StreamingResponse(
        generator(),
        media_type="application/octet-stream",
        headers={"X-Sample-Rate": str(sr)},
    )


# ── STT ───────────────────────────────────────────────────────────────────────

@router.post("/v1/stt")
async def stt(request: Request, audio: UploadFile = File(...)):
    raw = await audio.read()
    if not raw:
        raise HTTPException(status_code=400, detail="audio file is empty")

    service: InferenceService = request.app.state.inference_service
    converter = request.app.state.audio_converter

    # Convert any ffmpeg-compatible format to 16 kHz WAV for Parakeet
    try:
        wav_bytes = converter(raw, target_sr=service.settings.parakeet_sample_rate)
    except Exception as exc:
        logger.exception("Audio conversion failed")
        raise HTTPException(status_code=422, detail=f"Audio conversion failed: {exc}")

    with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
        tmp.write(wav_bytes)
        tmp_path = tmp.name

    try:
        text = await service.transcribe_async(tmp_path)
    except Exception as exc:
        logger.exception("Transcription failed")
        raise HTTPException(status_code=500, detail=str(exc))

    return {"text": text}


# Production app: constructed after all routes are registered so
# include_router picks up the full shipped surface (uvicorn src.main:app).
app = create_app()
