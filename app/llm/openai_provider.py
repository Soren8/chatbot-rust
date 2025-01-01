import openai
from app.llm.base_provider import BaseLLMProvider

class OpenAIProvider(BaseLLMProvider):
    """
    Provider for OpenAI or OpenAI-compatible endpoints.
    """

    def __init__(self, api_key, model="gpt-3.5-turbo"):
        openai.api_key = api_key
        self.model = model

    def generate_text_stream(self, prompt, system_prompt, session_history, memory_text):
        # Truncate memory if too long
        max_memory_length = 2000
        memory_text = memory_text[:max_memory_length]

        messages = []
        # System message
        messages.append({"role": "system", "content": system_prompt})

        # Optionally add memory/context
        if memory_text.strip():
            messages.append({"role": "system", "content": f"Memory:\n{memory_text}"})

        # Add conversation history
        for user_in, assistant_res in session_history:
            messages.append({"role": "user", "content": user_in})
            messages.append({"role": "assistant", "content": assistant_res})

        # Add final user prompt
        messages.append({"role": "user", "content": prompt})

        # Stream from OpenAI
        try:
            completion = openai.ChatCompletion.create(
                model=self.model,
                messages=messages,
                temperature=0.7,
                stream=True
            )
            for chunk in completion:
                if "choices" in chunk and len(chunk.choices) > 0:
                    delta = chunk.choices[0].delta
                    if "content" in delta:
                        yield delta["content"]
        except Exception as e:
            yield f"\n[Error] {str(e)}"
