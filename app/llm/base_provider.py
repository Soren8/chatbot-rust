from abc import ABC, abstractmethod

class BaseLLMProvider(ABC):
    @abstractmethod
    def generate_text_stream(self, prompt, system_prompt, session_history, memory_text, context_size):
        """
        Returns a generator that yields pieces of text from the LLM response.
        """
        pass
