import logging
from app.config import Config

logger = logging.getLogger(__name__)

def generate_text_stream(prompt, system_prompt, model_name, session_history, memory_text):
    logger.debug("Entered chat_logic.generate_text_stream()")
    logger.debug("Parameters received: prompt: %s, system_prompt: %s, model_name: %s",
                 prompt, system_prompt, model_name)
    logger.debug("Session history length: %d", len(session_history))
    if session_history:
        logger.debug("Last history item: %s", session_history[-1])

    # Look up the LLM configuration based on provider_name (which is derived from YAML's name or provider_name)
    llm_config = next((llm for llm in Config.LLM_PROVIDERS if llm["provider_name"] == model_name), None)
    if not llm_config:
        logger.error("No LLM configuration found for model name: %s", model_name)
        return

    provider_type = llm_config["type"].lower()
    
    # Create a copy of the config with sensitive fields truncated for logging
    safe_config = llm_config.copy()
    if "api_key" in safe_config and safe_config["api_key"]:
        safe_config["api_key"] = safe_config["api_key"][:8] + "..." if safe_config["api_key"] else ""
    
    logger.debug("LLM configuration found: %s", safe_config)

    # Instantiate the appropriate provider based on the configuration type.
    if provider_type == "ollama":
        from app.llm.ollama_provider import OllamaProvider
        provider = OllamaProvider(llm_config)  # Pass the llm_config so the provider knows its base_url, etc.
        logger.debug("Instantiated OllamaProvider (type 'ollama') as per configuration.")
    elif provider_type == "openai":
        from app.llm.openai_provider import OpenaiProvider
        provider = OpenaiProvider(llm_config)  # Pass the llm_config similarly.
        logger.debug("Instantiated OpenaiProvider (type 'openai') as per configuration.")
    else:
        logger.error("Unsupported provider type in configuration: %s. Must be 'ollama' or 'openai'.", provider_type)
        return

    try:
        # Invoke the provider's generate_text_stream to get a generator.
        provider_generator = provider.generate_text_stream(prompt, system_prompt, session_history, memory_text)
        logger.debug("Provider generator successfully obtained. Passing through chunks.")
        
        # Simply yield from the provider's generator. The frontend will handle parsing.
        for chunk in provider_generator:
            yield chunk
            
    except Exception as e:
        logger.exception("Exception encountered during provider generator iteration:")
        yield f"\n[Error] Exception during streaming: {str(e)}"

    logger.debug("Exiting chat_logic.generate_text_stream() after provider generator iteration.")
