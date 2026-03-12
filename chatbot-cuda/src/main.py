"""FastAPI voice service — TTS (Qwen3-TTS) and STT (Parakeet)."""

import logging
import os
import tempfile
from contextlib import asynccontextmanager
from typing import Optional

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
        "tts_loaded": models._tts_loaded,
        "stt_loaded": models._stt_loaded,
    }


# ── TTS ───────────────────────────────────────────────────────────────────────

class TtsRequest(BaseModel):
    text: str
    voice: str = "Ryan"
    voice_ref_audio: Optional[str] = None   # base64-encoded audio
    voice_ref_text: Optional[str] = None


@app.post("/v1/tts")
async def tts(req: TtsRequest):
    if not req.text.strip():
        raise HTTPException(status_code=400, detail="text is required")

    try:
        pcm, sr = models.synthesize(
            text=req.text,
            voice=req.voice,
            ref_audio=req.voice_ref_audio,
            ref_text=req.voice_ref_text,
        )
    except Exception as exc:
        logger.exception("TTS synthesis failed")
        raise HTTPException(status_code=500, detail=str(exc))

    return Response(
        content=pcm,
        media_type="application/octet-stream",
        headers={"X-Sample-Rate": str(sr)},
    )


@app.post("/v1/tts/stream")
async def tts_stream(req: TtsRequest):
    if not req.text.strip():
        raise HTTPException(status_code=400, detail="text is required")

    async def generator():
        try:
            async for chunk in models.synthesize_stream(
                text=req.text,
                voice=req.voice,
                ref_audio=req.voice_ref_audio,
                ref_text=req.voice_ref_text,
            ):
                yield chunk
        except Exception as exc:
            logger.exception("TTS stream failed")
            raise HTTPException(status_code=500, detail=str(exc))

    sr = models.tts_sample_rate()
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

    content_type = audio.content_type or "audio/webm"

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
        text = models.transcribe(tmp_path)
    except Exception as exc:
        logger.exception("Transcription failed")
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        os.unlink(tmp_path)

    return {"text": text}
