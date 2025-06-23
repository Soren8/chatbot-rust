import json
import logging
import requests
from app.llm.base_provider import BaseLLMProvider

logger = logging.getLogger(__name__)

class OllamaProvider(BaseLLMProvider):
    """Provider for Ollama endpoint configured via YAML"""

    def __init__(self, provider_config):
        # Store full config for logging
        self.provider_config = provider_config
        
        # Use model_name from config directly
        self.model_name = provider_config["model_name"]
        
        # Ensure base_url handling works with existing configs
        self.base_url = provider_config.get("base_url", "http://localhost:11434").rstrip("/")
        
        # Keep existing behavior for templates if needed 
        self.template = provider_config.get("template", "")
        
        self.context_size = provider_config.get("context_size", 4096)
        
        # Use standard generate endpoint
        self.url = f"{self.base_url}/api/generate"

    def generate_text_stream(self, prompt, system_prompt, session_history, memory_text):
        logger.debug(
            "Ollama Provider Configuration:\n"
            f"Model Name: {self.model_name}\n"
            f"Base URL: {self.base_url}\n"
            f"Context Size: {self.context_size}\n"
            f"Template Enabled: {bool(self.template)}"
        )
        
        data = {
            "model": self.model_name,
            "prompt": prompt,
            "system": system_prompt,
            "stream": True,
            "options": {
                "num_ctx": self.context_size
            }
        }

        # Log request details with sensitive fields truncated or removed
        safe_data = {
            **data,
            'prompt': data['prompt'][:50] + '...' if len(data['prompt']) > 50 else data['prompt']
        }
        
        logger.debug(
            "Ollama Request Details:\n"
            f"URL: {self.url}\n"
            f"Body preview: {json.dumps(safe_data, indent=2)}"
        )
        
        try:
            with requests.post(self.url, json=data, stream=True, timeout=300) as response:
                logger.debug(f"Received response from Ollama: HTTP {response.status_code}")
                response.raise_for_status()
                
                response_text = ""
                for line_number, line in enumerate(response.iter_lines()):
                    if line:
                        logger.debug(f"Processing line {line_number}: {line.decode()}")
                        try:
                            chunk = json.loads(line)
                            if "response" not in chunk:
                                logger.warning(
                                    "Unexpected Ollama response format:\n"
                                    f"{json.dumps(chunk, indent=2)}"
                                )
                            else:
                                logger.debug(f"Received valid response chunk: {chunk['response']}")
                                
                            response_part = chunk.get("response", "")
                            response_text += response_part
                            yield response_part
                            
                        except json.JSONDecodeError:
                            logger.error(
                                "Failed to parse JSON from line:\n"
                                f"Raw line content: {line.decode()}"
                            )
                            yield ""
                            
                logger.debug(
                    f"Ollama request completed\n"
                    f"Total response length: {len(response_text)} characters\n"
                    f"First 200 chars: {response_text[:200]}"
                )
                
        except requests.exceptions.RequestException as e:
            # Use the safe_data variable we created earlier to avoid logging sensitive information
            logger.error(
                "Ollama connection failed\n"
                f"URL: {self.url}\n"
                f"Error: {str(e)}\n"
                f"Request data: {json.dumps(safe_data, indent=2)}"
            )
            yield f"\n⚠️ Connection error: {str(e)}"
