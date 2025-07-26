import logging
from app.config import Config

logger = logging.getLogger(__name__)

def calculate_available_history_tokens(context_size, system_prompt, memory_text):
    """Calculate how many tokens we can use for history given system prompt and memory"""
    system_prompt_tokens = int(len(system_prompt) / 4)  # rough estimate of 1 token per 4 chars
    memory_tokens = int(len(memory_text) / 4) if memory_text else 0
    reserved_tokens = system_prompt_tokens + memory_tokens + int(context_size * Config.SYSTEM_PROMPT_BUFFER)
    return max(0, context_size - reserved_tokens)

def truncate_history(session_history, available_tokens):
    """Truncate history to fit in available tokens, prioritizing recent messages"""
    truncated_history = []
    total_tokens = 0
    
    # Iterate history in reverse (newest first)
    for user_msg, assistant_msg in reversed(session_history):
        user_tokens = len(user_msg) / 4
        assistant_tokens = len(assistant_msg) / 4
        combined_tokens = user_tokens + assistant_tokens
        
        if total_tokens + combined_tokens > available_tokens:
            # If we're over limit, try to add partial messages from the middle
            remaining_tokens = available_tokens - total_tokens
            if remaining_tokens > 100:  # Only add partial if there's meaningful space
                user_part = user_msg[:int(remaining_tokens * 2)]  # *2 because 0.5 tokens per char
                assistant_part = assistant_msg[:int(remaining_tokens * 2)]
                truncated_history.insert(0, (user_part, assistant_part))
            break
            
        truncated_history.insert(0, (user_msg, assistant_msg))
        total_tokens += combined_tokens
    
    return truncated_history

def generate_text_stream(prompt, system_prompt, model_name, full_history, memory_text):
    logger.debug("Entered chat_logic.generate_text_stream()")
    logger.debug("Parameters received: prompt: %s, system_prompt: %s, model_name: %s",
                 prompt, system_prompt, model_name)
    logger.debug("Full history length: %d", len(full_history))
    if full_history:
        logger.debug("First history item: %s", full_history[0])
        logger.debug("Last history item: %s", full_history[-1])
        logger.debug("History items: %s", [f"{len(user)}/{len(assistant)}" for user, assistant in full_history])

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

    # Get context size from config
    context_size = llm_config.get("context_size", Config.MODEL_CONTEXT_SIZE)
    
    # Calculate available tokens for history and truncate a copy if needed
    available_tokens = calculate_available_history_tokens(context_size, system_prompt, memory_text)
    truncated_history = truncate_history(full_history, available_tokens)
    
    if len(truncated_history) < len(full_history):
        logger.warning("Truncated chat history from %d to %d messages to fit in context window", 
                      len(full_history), len(truncated_history))
        logger.debug("Original history length in tokens: %d", sum(len(u)+len(a) for u,a in full_history)//4)
        logger.debug("Truncated history length in tokens: %d", sum(len(u)+len(a) for u,a in truncated_history)//4)
    
    # Instantiate the appropriate provider based on the configuration type.
    if provider_type == "ollama":
        from app.llm.ollama_provider import OllamaProvider
        provider = OllamaProvider(llm_config)
        logger.debug("Instantiated OllamaProvider (type 'ollama') as per configuration.")
    elif provider_type == "openai":
        from app.llm.openai_provider import OpenaiProvider
        provider = OpenaiProvider(llm_config)
        logger.debug("Instantiated OpenaiProvider (type 'openai') as per configuration.")
    else:
        logger.error("Unsupported provider type in configuration: %s. Must be 'ollama' or 'openai'.", provider_type)
        return

    try:
        # Invoke the provider's generate_text_stream with truncated history
        provider_generator = provider.generate_text_stream(
            prompt, 
            system_prompt, 
            truncated_history, 
            memory_text,
            context_size
        )
        logger.debug("Provider generator successfully obtained. Passing through chunks.")
        
        # Simply yield from the provider's generator. The frontend will handle parsing.
        for chunk in provider_generator:
            yield chunk
            
    except Exception as e:
        logger.exception("Exception encountered during provider generator iteration:")
        yield f"\n[Error] Exception during streaming: {str(e)}"

    logger.debug("Exiting chat_logic.generate_text_stream() after provider generator iteration.")
