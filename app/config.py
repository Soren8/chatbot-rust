import os
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "default_secret_key")
    LLM_PROVIDER = os.getenv("LLM_PROVIDER", "ollama")
    MODEL_NAME = os.getenv("MODEL_NAME", "dolphin3.1-8b")
    MODEL_CONTEXT_SIZE = int(os.getenv("MODEL_CONTEXT_SIZE", "8192"))
    CONTEXT_SLIDE_SIZE = int(MODEL_CONTEXT_SIZE * 0.75)  # 75% of window size
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    OLLAMA_HOST = os.getenv("OLLAMA_HOST", "localhost")
    OLLAMA_PORT = os.getenv("OLLAMA_PORT", "11434")
    SESSION_TIMEOUT = 3600  # 1 hour in seconds

    # TTS Configuration
    TTS_HOST = os.getenv("TTS_HOST", "localhost")
    TTS_PORT = os.getenv("TTS_PORT", "5000")
    TTS_BASE_URL = f"http://{TTS_HOST}:{TTS_PORT}"
