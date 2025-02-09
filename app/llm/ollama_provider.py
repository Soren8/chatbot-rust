import json
import logging
import requests
from app.llm.base_provider import BaseLLMProvider

logger = logging.getLogger(__name__)

class OllamaProvider(BaseLLMProvider):
    """Provider for Ollama endpoint configured via YAML"""

    def __init__(self, provider_config):
        # Use model_name from config directly
        self.model_name = provider_config["model_name"]
        
        # Ensure base_url handling works with existing configs
        self.base_url = provider_config.get("base_url", "http://localhost:11434").rstrip("/")
        
        # Keep existing behavior for templates if needed 
        self.template = provider_config.get("template", "")
        
        self.context_size = provider_config.get("context_size", 4096)
        
        # Use standard generate endpoint
        self.url = f"{self.base_url}/api/generate"

    def generate_text_stream(self, final_prompt):
        data = {
            "model": self.model_name,
            "prompt": final_prompt,
            "stream": True,
            "options": {
                "num_ctx": self.context_size
            }
        }

        logger.debug(f"Sending to Ollama at {self.url}: {data}")
        
        try:
            with requests.post(self.url, json=data, stream=True, timeout=30) as response:
                response.raise_for_status()
                for line in response.iter_lines():
                    if line:
                        try:
                            chunk = json.loads(line)
                            # Ollama's response format verification
                            if "response" not in chunk:
                                logger.warning(f"Unexpected Ollama response: {chunk}")
                            yield chunk.get("response", "")
                        except json.JSONDecodeError:
                            logger.error("Failed to parse Ollama response line")
                            yield ""
        except requests.exceptions.RequestException as e:
            logger.error(f"Ollama connection failed: {e}")
            yield f"\n⚠️ Connection error: {str(e)}"
