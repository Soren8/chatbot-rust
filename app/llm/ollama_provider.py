import json
import requests
from app.llm.base_provider import BaseLLMProvider

class OllamaProvider(BaseLLMProvider):
    """
    Provider for Ollama endpoint (e.g., running locally on port 11434).
    """

    def __init__(self, model_name="dolphin3.1-8b"):
        self.model_name = model_name
        from app.config import Config
        self.url = f"http://{Config.OLLAMA_HOST}:{Config.OLLAMA_PORT}/api/generate"

    def generate_text_stream(self, prompt, system_prompt, session_history, memory_text):
        from app.config import Config
        
        # Truncate memory if too long relative to context size
        max_memory_length = int(Config.MODEL_CONTEXT_SIZE * 0.2)  # 20% of context size
        memory_text = memory_text[:max_memory_length]

        # Build the prompt
        if not session_history:
            history_text = f"### System: {system_prompt}\n\n"
        else:
            history_text = ""

        if memory_text.strip():
            history_text += f"### Memory:\n{memory_text}\n\n"

        for user_input, assistant_response in session_history:
            history_text += f"### User:\n{user_input}\n\n### Assistant:\n{assistant_response}\n\n"

        # Append latest user prompt
        history_text += f"### User:\n{prompt}\n\n### Assistant:\n"

        data = {
            "model": self.model_name,
            "prompt": history_text,
            "system": system_prompt,
            "stream": True,
            "options": {
                "num_ctx": Config.MODEL_CONTEXT_SIZE
            }
        }

        with requests.post(self.url, json=data, stream=True) as response:
            if response.status_code == 200:
                for line in response.iter_lines():
                    if line:
                        json_response = json.loads(line)
                        if 'response' in json_response:
                            yield json_response['response']
            else:
                yield f"\n[Error] Error: {response.status_code}, {response.text}"
