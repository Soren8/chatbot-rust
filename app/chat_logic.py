import logging
from app.llm.ollama_provider import OllamaProvider
from app.llm.openai_provider import OpenAIProvider

logger = logging.getLogger(__name__)

def get_llm_provider(config):
    """
    Decide which LLM provider to use, based on configuration.
    """
    provider_name = config.get('LLM_PROVIDER', 'ollama')
    model_name = config.get('MODEL_NAME', 'dolphin3.1-8b')
    openai_key = config.get('OPENAI_API_KEY', '')

    if provider_name.lower() == 'openai':
        return OpenAIProvider(api_key=openai_key, model=model_name)
    else:
        return OllamaProvider(model_name=model_name)

def generate_text_stream(prompt, system_prompt, model_name, session_history, memory_text, config):
    """
    Get the appropriate LLM provider and stream the response.
    """
    llm = get_llm_provider(config)
    
    # Ensure memory_text is not None
    if memory_text is None:
        memory_text = ""
    
    # Debug log to verify memory is being passed
    logger.debug(f"Generating text with memory: {memory_text[:50]}...")
    
    return llm.generate_text_stream(
        prompt=prompt,
        system_prompt=system_prompt,
        session_history=session_history,
        memory_text=memory_text
    )
