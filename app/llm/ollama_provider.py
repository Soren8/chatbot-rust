from jinja2 import Template
import json
import requests
from app.llm.base_provider import BaseLLMProvider

class OllamaProvider(BaseLLMProvider):
    """Provider for Ollama endpoint configured via YAML"""

    def __init__(self, provider_config):
        self.model_name = provider_config["model_name"]
        self.base_url = provider_config["base_url"].rstrip("/")
        self.template = provider_config.get("template", "")
        self.context_size = provider_config.get("context_size", 4096)
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

        try:
            with requests.post(self.url, json=data, stream=True, timeout=30) as response:
                response.raise_for_status()
                for line in response.iter_lines():
                    if line:
                        chunk = json.loads(line)
                        yield chunk.get("response", "")
        except requests.exceptions.RequestException as e:
            yield f"\n[Error] Connection error: {str(e)}"
