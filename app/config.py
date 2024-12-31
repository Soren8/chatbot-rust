import os
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "default_secret_key")
    LLM_PROVIDER = os.getenv("LLM_PROVIDER", "ollama")
    MODEL_NAME = os.getenv("MODEL_NAME", "dolphin3.1-8b")
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    SESSION_TIMEOUT = 3600  # 1 hour in seconds

    # Additional configuration can go here.
