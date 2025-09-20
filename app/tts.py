from flask import jsonify, request, Response
import re
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
    logger.debug("Starting TTS audio generation")
    # Clean and validate input text
    # Remove thinking tags and content
    text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL).strip()
    if not text:
        logger.debug("Empty text provided to generate_tts_audio")
        raise ValueError("Empty text provided")
    
    # Prepare API request using config values
    api_url = f"{Config.TTS_BASE_URL}/api/tts"
    payload = {
        "text": text,
        "voice_file": "voices/default.wav"
    }
    logger.debug(f"Preparing TTS request to {api_url}")
    
    try:
        # Make API request
        logger.debug("Making TTS API request")
        response = requests.post(
            api_url,
            json=payload,
            timeout=30  # 30 second timeout
        )
        logger.debug(f"Received response with status code: {response.status_code}")
        
        # Handle API errors
        if response.status_code != 200:
            error_msg = response.json().get("error", "Unknown error")
            logger.error(f"TTS API error: {error_msg}")
            raise RuntimeError(f"TTS API error: {error_msg}")
        
        # Convert response to WAV format in memory
        logger.debug("Converting response to WAV format")
        audio_data = BytesIO()
        with wave.open(audio_data, 'wb') as wav_file:
            wav_file.setnchannels(1)  # Mono
            wav_file.setsampwidth(2)  # 16-bit
            wav_file.setframerate(22050)  # 22.05 kHz
            wav_file.writeframes(response.content)
        
        # Reset buffer position for reading
        audio_data.seek(0)
        logger.debug("TTS audio generation completed successfully")
        return audio_data
        
    except requests.exceptions.RequestException as e:
        logger.error(f"TTS API connection failed: {str(e)}", exc_info=True)
        raise RuntimeError(f"TTS API connection failed: {str(e)}")

def register_tts_routes(bp):
    # Keep the simple route for the web client
    @bp.route("/tts", methods=["POST"])
    def tts():
        """Web-facing TTS endpoint used by the frontend (POST /tts)."""
        return _handle_tts_request()

    # Keep only the legacy `/tts` endpoint to match the old Flask
    # behavior exactly. The axum/Rust layer should proxy requests to
    # this same `/tts` path so frontend code does not need to change.


def _handle_tts_request():
    """Common handler for TTS requests used by multiple routes."""
    logger.debug("TTS request received")
    if not request.is_json:
        logger.debug("TTS request missing JSON body")
        return jsonify({"error": "JSON body required"}), 400

    text = request.json.get("text", "")
    logger.debug(f"Received text: {text[:100]}...")  # Log first 100 chars

    if not text:
        logger.debug("Empty text received")
        return jsonify({"error": "No text provided"}), 400

    try:
        logger.debug(f"Generating TTS for text: {text[:50]}...")
        audio_data = generate_tts_audio(text)
        logger.debug("TTS generation successful")
        return Response(
            audio_data.getvalue(),
            mimetype="audio/wav",
            headers={"Content-Disposition": "inline; filename=tts.wav"},
        )
    except Exception as e:
        logger.error(f"TTS generation failed: {str(e)}", exc_info=True)
        return jsonify({"error": "TTS generation failed"}), 500
