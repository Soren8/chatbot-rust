import logging
from importlib import import_module
from app.config import Config

logger = logging.getLogger(__name__)

def get_llm_provider(model_name=None):
    """Get the configured LLM provider based on model name"""
    # Use default model if none specified
    if not model_name and Config.DEFAULT_LLM:
        model_name = Config.DEFAULT_LLM["provider_name"]  # Use provider name for lookup
    
    # Find provider configuration
    provider_config = next(
        (llm for llm in Config.LLM_PROVIDERS if llm["provider_name"] == model_name),
        None
    )
    
    if not provider_config:
        raise ValueError(f"No provider found for model: {model_name}")
    
    # Dynamically import provider class
    try:
        module = import_module(f"app.llm.{provider_config['type']}_provider")
        provider_class = getattr(module, f"{provider_config['type'].title()}Provider")  # e.g. "OllamaProvider"
    except (ImportError, AttributeError) as e:
        raise RuntimeError(f"Failed to load provider {provider_config['type']}: {str(e)}")

    return provider_class(provider_config)

def generate_text_stream(prompt, system_prompt, model_name, session_history, memory_text):
    """Generate streaming response from LLM"""
    # Get configured provider
    provider = get_llm_provider(model_name)
    
    logger.debug(
        "Starting text generation with parameters:\n"
        f"- Provider: {provider.provider_config['provider_name']}\n"
        f"- Model: {provider.provider_config['model_name']}\n"
        f"- System Prompt: {system_prompt[:200]}...\n" 
        f"- User Prompt: {prompt[:200]}...\n"
        f"- Memory Length: {len(memory_text)} chars\n"
        f"- History Length: {len(session_history)} exchanges"
    )

    # Generate the response stream using raw prompt
    try:
        return provider.generate_text_stream(
            prompt=prompt,
            system_prompt=system_prompt,
            session_history=session_history,
            memory_text=memory_text
        )
    except Exception as e:
        logger.error(f"Generation failed: {str(e)}")
        yield f"\n[Error] Response generation failed: {str(e)}"
