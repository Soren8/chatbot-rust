import os
import yaml
import logging
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()  # Load environment variables first

class Config:
    # Core application settings
    SECRET_KEY = os.getenv("SECRET_KEY", "default_secret_key")
    HOST_DATA_DIR = os.getenv("HOST_DATA_DIR", "./data")
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    
    @classmethod
    def configure_logging(cls):
        """Configure logging for the application"""
        logging.basicConfig(
            level=cls.LOG_LEVEL,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
    # TTS configuration
    TTS_BASE_URL = f"http://{os.getenv('TTS_HOST', 'localhost')}:{os.getenv('TTS_PORT', '5000')}"
    
    # LLM configuration (initial values, will be overridden by YAML)
    LLM_PROVIDERS = []
    MODEL_NAME = "dolphin3.1-8b"
    MODEL_CONTEXT_SIZE = 8192
    CONTEXT_SLIDE_SIZE = 6144  # 75% of 8192
    SESSION_TIMEOUT = 3600
    DEFAULT_LLM = None

    @classmethod
    def load_config(cls):
        """Load YAML configuration and process environment variables"""
        config_path = Path(".config.yml")
        
        # Verify config path is a file
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file {config_path.absolute()} not found")
        if not config_path.is_file():
            raise IsADirectoryError(f"Configuration path {config_path.absolute()} is a directory - must be a file")

        try:
            with open(config_path) as f:
                raw_config = yaml.safe_load(f) or {}

            # Process environment variable substitution
            processed_config = cls._replace_env_vars(raw_config)
            
            # Load LLM configurations
            cls._load_llm_config(processed_config)

        except yaml.YAMLError as e:
            raise RuntimeError(f"Invalid YAML syntax in {config_path}: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"Error processing {config_path}: {str(e)}")

    @staticmethod
    def _replace_env_vars(config):
        """Recursively replace ${ENV_VAR} patterns in configuration"""
        if isinstance(config, dict):
            return {k: Config._replace_env_vars(v) for k, v in config.items()}
        elif isinstance(config, list):
            return [Config._replace_env_vars(elem) for elem in config]
        elif isinstance(config, str) and config.startswith("${") and config.endswith("}"):
            env_var = config[2:-1]
            return os.getenv(env_var, "")
        return config

    @classmethod
    def _load_llm_config(cls, config):
        """Process LLM configuration from YAML"""
        cls.LLM_PROVIDERS = []
        
        required_fields = ["provider_name", "type", "model_name"]
        
        for idx, llm in enumerate(config.get("llms", [])):
            # Validate required fields
            # Validate required fields with more helpful error messages
            # Allow legacy 'name' field as alias for 'provider_name'
            if "name" in llm and "provider_name" not in llm:
                llm["provider_name"] = llm["name"]
            missing_fields = [field for field in required_fields if field not in llm]
            if missing_fields:
                raise ValueError(
                    f"LLM configuration entry {idx+1} is missing required fields: {', '.join(missing_fields)}. "
                    f"Found fields: {', '.join(llm.keys())}"
                )
                    
            provider = {
                "provider_name": llm.get("provider_name", llm.get("name")),  # Backwards compatibility
                "type": llm["type"],
                "tier": llm.get("tier", "free"),
                "model_name": llm["model_name"],  # Required field, will raise KeyError if missing
                "context_size": llm.get("context_size", cls.MODEL_CONTEXT_SIZE),
                "base_url": llm.get("base_url", ""),
                "api_key": llm.get("api_key", ""),
                "template": llm.get("template")
            }
            cls.LLM_PROVIDERS.append(provider)
        
        # Set default model if configured
        default_name = config.get("default_llm", "")
        if default_name:
            for llm in cls.LLM_PROVIDERS:
                if llm["provider_name"] == default_name:
                    cls.DEFAULT_LLM = llm
                    break
        else:
            cls.DEFAULT_LLM = cls.LLM_PROVIDERS[0] if cls.LLM_PROVIDERS else None

        # Override session timeout if specified
        cls.SESSION_TIMEOUT = config.get("session_timeout", 3600)

# Initialize configuration when module loads
try:
    Config.load_config()
except Exception as e:
    raise RuntimeError(f"Failed to load configuration: {str(e)}")
