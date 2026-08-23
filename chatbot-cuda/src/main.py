"""FastAPI voice service — TTS (Kokoro) and STT (Parakeet)."""

import asyncio
import logging
import os
import tempfile
from contextlib import asynccontextmanager

from fastapi import FastAPI, File, HTTPException, Response, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from . import models
from .audio_utils import webm_to_wav_bytes

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

PARAKEET_SR = 16_000  # Parakeet TDT expects 16 kHz input


@asynccontextmanager
async def lifespan(app: FastAPI):
    models.load_models()
    yield


app = FastAPI(title="Voice Service", lifespan=lifespan)


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status": "ok",
        "kokoro_loaded": models._kokoro_loaded,
        "stt_loaded": models._stt_loaded,
    }


# ── Kokoro TTS ────────────────────────────────────────────────────────────────

class KokoroTtsRequest(BaseModel):
    text: str
    voice: str = "af_heart"


@app.post("/v1/tts/kokoro")
async def kokoro_tts(req: KokoroTtsRequest):
    if not req.text.strip():
        raise HTTPException(status_code=400, detail="text is required")

    try:
        pcm, sr = await asyncio.to_thread(
            models.synthesize_kokoro,
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


@app.post("/v1/tts/kokoro/stream")
async def kokoro_tts_stream(req: KokoroTtsRequest):
    if not req.text.strip():
        raise HTTPException(status_code=400, detail="text is required")

    async def generator():
        try:
            async for chunk in models.synthesize_kokoro_stream(
                text=req.text,
                voice=req.voice,
            ):
                yield chunk
        except Exception as exc:
            logger.exception("Kokoro TTS stream failed")
            raise HTTPException(status_code=500, detail=str(exc))

    sr = models.kokoro_sample_rate()
    return StreamingResponse(
        generator(),
        media_type="application/octet-stream",
        headers={"X-Sample-Rate": str(sr)},
    )


# ── STT ───────────────────────────────────────────────────────────────────────

@app.post("/v1/stt")
async def stt(audio: UploadFile = File(...)):
    raw = await audio.read()
    if not raw:
        raise HTTPException(status_code=400, detail="audio file is empty")

    # Convert any ffmpeg-compatible format to 16 kHz WAV for Parakeet
    try:
        wav_bytes = webm_to_wav_bytes(raw, target_sr=PARAKEET_SR)
    except Exception as exc:
        logger.exception("Audio conversion failed")
        raise HTTPException(status_code=422, detail=f"Audio conversion failed: {exc}")

    with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
        tmp.write(wav_bytes)
        tmp_path = tmp.name

    try:
        text = await asyncio.to_thread(models.transcribe, tmp_path)
    except Exception as exc:
        logger.exception("Transcription failed")
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        os.unlink(tmp_path)

    return {"text": text}
