from flask import jsonify, request, Response
import logging
from io import BytesIO
import requests
import numpy as np
import wave
from typing import Optional
from app.config import Config

logger = logging.getLogger(__name__)

def generate_tts_audio(text: str) -> BytesIO:
    """
    Generate TTS audio from text using the external API.
    Returns a BytesIO object containing the audio data in WAV format.
    """
    # Clean and validate input text
    text = text.strip()
    if not text:
        raise ValueError("Empty text provided")
    
    # Prepare API request
    api_url = "http://localhost:5000/api/tts"
    payload = {
        "text": text,
        "voice_file": "voices/default.wav"
    }
    
    try:
        # Make API request
        response = requests.post(
            api_url,
            json=payload,
            timeout=30  # 30 second timeout
        )
        
        # Handle API errors
        if response.status_code != 200:
            error_msg = response.json().get("error", "Unknown error")
            raise RuntimeError(f"TTS API error: {error_msg}")
        
        # Convert response to WAV format in memory
        audio_data = BytesIO()
        with wave.open(audio_data, 'wb') as wav_file:
            wav_file.setnchannels(1)  # Mono
            wav_file.setsampwidth(2)  # 16-bit
            wav_file.setframerate(22050)  # 22.05 kHz
            wav_file.writeframes(response.content)
        
        # Reset buffer position for reading
        audio_data.seek(0)
        return audio_data
        
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"TTS API connection failed: {str(e)}")

def register_tts_routes(bp):
    @bp.route("/tts", methods=["POST"])
    def tts():
        """
        Minimal TTS endpoint that handles the HTTP communication.
        Delegates actual TTS generation to generate_tts_audio().
        """
        text = request.json.get("text", "")
        if not text:
            return jsonify({"error": "No text provided"}), 400

        try:
            logger.debug(f"Generating TTS for text: {text[:50]}...")
            audio_data = generate_tts_audio(text)
            return Response(
                audio_data.getvalue(),
                mimetype="audio/mpeg",
                headers={
                    "Content-Disposition": "inline; filename=tts.mp3"
                }
            )
        except Exception as e:
            logger.error(f"TTS generation failed: {str(e)}")
            return jsonify({"error": "TTS generation failed"}), 500
