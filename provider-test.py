import argparse
import yaml
from app.llm.openai_provider import OpenAIProvider
from app.llm.ollama_provider import OllamaProvider

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

    config = load_config().get(args.provider)
    if not config:
        exit(f"Missing configuration for {args.provider} provider")

    # Additional check for OpenAI provider
    if args.provider == 'openai' and 'openai_api_key' not in config:
        exit("Error: 'openai_api_key' is required in provider-test.yml for OpenAI provider")

    # Initialize provider
    if args.provider == 'openai':
        provider = OpenAIProvider(config)
    else:  # ollama
        provider = OllamaProvider(config)

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
