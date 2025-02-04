from openai import OpenAI
from app.llm.base_provider import BaseLLMProvider

class OpenAIProvider(BaseLLMProvider):
    """
    Provider for OpenAI or OpenAI-compatible endpoints.
    """

    def __init__(self, config):
        # Validate required fields
        required_keys = ['api_key']
        missing = [key for key in required_keys if key not in config]
        if missing:
            raise ValueError(f"Missing required keys in provider-test.yml: {missing}")

        # Initialize the client with the config
        self.client = OpenAI(
            api_key=config['api_key'],  # From provider-test.yml
            base_url=config.get('base_url', 'https://api.openai.com/v1'),  # From provider-test.yml
            timeout=config.get('request_timeout', 30.0)  # From provider-test.yml
        )
        self.model = config.get('model', 'gpt-4')  # From provider-test.yml

    def generate_text_stream(self, prompt, system_prompt, session_history, memory_text):
        messages = [{"role": "system", "content": system_prompt}]

        if memory_text.strip():
            messages.append({"role": "system", "content": f"Memory:\n{memory_text[:2000]}"})

        for user_in, assistant_res in session_history:
            messages.append({"role": "user", "content": user_in})
            if assistant_res:  # Allow empty responses in history
                messages.append({"role": "assistant", "content": assistant_res})

        messages.append({"role": "user", "content": prompt})

        try:
            stream = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0.7,
                stream=True
            )
            
            for chunk in stream:
                content = chunk.choices[0].delta.content
                if content is not None:
                    yield content

        except Exception as e:
            yield f"\n[Error]: {str(e)}"
