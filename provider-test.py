import logging
import argparse
import yaml
from app.llm.openai_provider import OpenAIProvider
from app.llm.ollama_provider import OllamaProvider

# Set global logging level and configure specific modules
logging.basicConfig(level=logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)  # Add this line
logging.getLogger("httpx").setLevel(logging.WARNING)     # Add this line

def load_config():
    try:
        with open("provider-test.yml") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        exit("Error: provider-test.yml not found")

def main():
    parser = argparse.ArgumentParser(description='Test LLM Providers')
    parser.add_argument('--provider', choices=['openai', 'ollama'], required=True)
    parser.add_argument('--prompt', type=str, help='Test prompt to send')
    args = parser.parse_args()

    # Load the full config from provider-test.yml
    config = load_config()
    if not config:
        exit("Error: provider-test.yml is empty or invalid")

    # Get the specific provider config
    provider_config = config.get(args.provider)
    if not provider_config:
        exit(f"Missing configuration for {args.provider} provider")

    # Additional check for OpenAI provider
    if args.provider == 'openai' and 'api_key' not in provider_config:
        exit("Error: 'api_key' is required under 'openai' section in provider-test.yml")

    # Initialize provider
    if args.provider == 'openai':
        provider = OpenAIProvider(provider_config)
    else:  # ollama
        provider = OllamaProvider(provider_config)

    # Run test
    prompt = args.prompt or "Write a short poem about AI assistants"
    response = provider.generate_text_stream(
        prompt=prompt,
        system_prompt="You are a helpful assistant",
        session_history=[],
        memory_text=""
    )

    print(f"\n{'-'*10} RESPONSE {'-'*10}")
    for chunk in response:
        print(chunk, end="", flush=True)
    print("\n" + "-"*30)

if __name__ == "__main__":
    main()
