from flask import current_app
from app.llm.ollama_provider import OllamaProvider
from app.llm.openai_provider import OpenAIProvider

def get_llm_provider():
    """
    Decide which LLM provider to use, based on environment config.
    """
    provider_name = current_app.config.get('LLM_PROVIDER', 'ollama')
    model_name = current_app.config.get('MODEL_NAME', 'dolphin3.1-8b')
    openai_key = current_app.config.get('OPENAI_API_KEY', '')

    if provider_name.lower() == 'openai':
        return OpenAIProvider(api_key=openai_key, model=model_name)
    else:
        return OllamaProvider(model_name=model_name)

def generate_text_stream(prompt, system_prompt, session_history, memory_text):
    """
    Get the appropriate LLM provider and stream the response.
    """
    llm = get_llm_provider()
    return llm.generate_text_stream(prompt, system_prompt, session_history, memory_text)
