import logging
from importlib import import_module
from jinja2 import Template
from app.config import Config

logger = logging.getLogger(__name__)

def get_llm_provider(model_name=None):
    """Get the configured LLM provider based on model name"""
    # Use default model if none specified
    if not model_name and Config.DEFAULT_LLM:
        model_name = Config.DEFAULT_LLM["name"]
    
    # Find provider configuration
    provider_config = next(
        (llm for llm in Config.LLM_PROVIDERS if llm["name"] == model_name),
        None
    )
    
    if not provider_config:
        raise ValueError(f"No provider found for model: {model_name}")
    
    # Dynamically import provider class
    try:
        module = import_module(f"app.llm.{provider_config['type']}_provider")
        provider_class = getattr(module, f"{provider_config['type'].title()}Provider")
    except (ImportError, AttributeError) as e:
        raise RuntimeError(f"Failed to load provider {provider_config['type']}: {str(e)}")

    return provider_class(provider_config)

def generate_text_stream(prompt, system_prompt, model_name, session_history, memory_text):
    """Generate streaming response from LLM"""
    # Get configured provider
    provider = get_llm_provider(model_name)
    
    # Apply template if configured
    final_prompt = prompt
    if provider.template:
        try:
            final_prompt = Template(provider.template).render(
                system_prompt=system_prompt,
                prompt=prompt,
                memory=memory_text,
                history=session_history
            )
        except Exception as e:
            logger.error(f"Template rendering failed: {str(e)}")
            final_prompt = f"{system_prompt}\n{prompt}"  # Fallback format

    # Generate the response stream
    try:
        return provider.generate_text_stream(final_prompt)
    except Exception as e:
        logger.error(f"Generation failed: {str(e)}")
        yield f"\n[Error] Response generation failed: {str(e)}"
