import os
import tempfile


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
