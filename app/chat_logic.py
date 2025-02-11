import logging
from importlib import import_module
from jinja2 import Template
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
    logger.debug(
        "Starting text generation with parameters:\n"
        f"- Model: {model_name}\n"
        f"- System Prompt: {system_prompt[:200]}...\n" 
        f"- User Prompt: {prompt[:200]}...\n"
        f"- Memory Length: {len(memory_text)} chars\n"
        f"- History Length: {len(session_history)} exchanges"
    )
    
    # Get configured provider
    provider = get_llm_provider(model_name)
    
    # Apply template if configured
    final_prompt = prompt
    if provider.template:
        try:
            final_prompt = Template(provider.template).render(
                system_prompt=system_prompt,
                prompt=prompt,
                memory_text=memory_text,
                history=session_history
            )
            logger.debug(
                "Applying template:\n"
                f"Template Content:\n{provider.template[:500]}...\n"
                f"Rendered Prompt:\n{final_prompt}"
            )
        except Exception as e:
            logger.error(f"Template rendering failed: {str(e)}")
            final_prompt = f"{system_prompt}\n{prompt}"  # Fallback format
    else:
        logger.debug("No template configured - using raw prompt")

    # Generate the response stream
    try:
        return provider.generate_text_stream(final_prompt)
    except Exception as e:
        logger.error(f"Generation failed: {str(e)}")
        yield f"\n[Error] Response generation failed: {str(e)}"
