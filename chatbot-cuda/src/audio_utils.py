import io
import os
import tempfile

import numpy as np
import soundfile as sf


def webm_to_wav_bytes(audio_bytes: bytes, target_sr: int = 16000) -> bytes:
    """Convert WebM/Opus (or any ffmpeg-compatible format) to WAV at target_sr."""
    import subprocess

    with tempfile.NamedTemporaryFile(suffix=".webm", delete=False) as tmp_in:
        tmp_in.write(audio_bytes)
        tmp_in_path = tmp_in.name

    tmp_out_path = tmp_in_path.replace(".webm", ".wav")
    try:
        result = subprocess.run(
            [
                "ffmpeg", "-y",
                "-i", tmp_in_path,
                "-ar", str(target_sr),
                "-ac", "1",
                "-f", "wav",
                tmp_out_path,
            ],
            capture_output=True,
        )
        if result.returncode != 0:
            stderr = result.stderr.decode(errors="replace")
            raise RuntimeError(
                f"ffmpeg exited {result.returncode}: {stderr[-500:]}"
            )
        with open(tmp_out_path, "rb") as f:
            return f.read()
    finally:
        os.unlink(tmp_in_path)
        if os.path.exists(tmp_out_path):
            os.unlink(tmp_out_path)


def wav_bytes_to_array(wav_bytes: bytes, target_sr: int = 16000):
    """Read WAV bytes into a float32 numpy array, resampling to target_sr if needed."""
    buf = io.BytesIO(wav_bytes)
    audio, sr = sf.read(buf, dtype="float32", always_2d=False)
    if sr != target_sr:
        import librosa
        audio = librosa.resample(audio, orig_sr=sr, target_sr=target_sr)
    return audio, target_sr


def numpy_to_pcm16(audio: np.ndarray) -> bytes:
    """Convert float32 numpy waveform [-1, 1] to raw 16-bit little-endian PCM bytes."""
    clipped = np.clip(audio, -1.0, 1.0)
    pcm = (clipped * 32767).astype(np.int16)
    return pcm.tobytes()


def numpy_to_wav_bytes(audio: np.ndarray, sample_rate: int) -> bytes:
    """Encode a float32 numpy waveform to WAV bytes."""
    buf = io.BytesIO()
    sf.write(buf, audio, sample_rate, format="WAV", subtype="PCM_16")
    buf.seek(0)
    return buf.read()
