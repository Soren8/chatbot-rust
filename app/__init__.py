from flask import Flask
from app.config import Config
from app.routes import register_routes
import logging

# Initialize logging before anything else
Config.configure_logging()

def create_app():
    # Verify logging configuration
    logger = logging.getLogger(__name__)
    
    # Debug logging configuration state
    root_logger = logging.getLogger()
    logger.debug(f"Root logger level: {root_logger.level}")
    logger.debug(f"App logger level: {logger.getEffectiveLevel()}")
    logger.debug(f"OllamaProvider logger level: {logging.getLogger('app.llm.ollama_provider').getEffectiveLevel()}")

    logger.debug(
        "Initializing application with configuration:\n"
        f"Log Level: {Config.LOG_LEVEL}\n"
        f"LLM Providers: {len(Config.LLM_PROVIDERS)} configured\n"
        f"Default LLM: {Config.DEFAULT_LLM['provider_name'] if Config.DEFAULT_LLM else 'None'}"
    )
    
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Configure third-party loggers
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.INFO)

    # Register all application routes
    register_routes(app)

    return app
