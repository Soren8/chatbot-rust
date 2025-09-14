# AGENTS.md - Development Guide

## Build & Run Commands
- Start app (dev): `flask run` or `python -m app`
- Run in Docker: `docker-compose up --build`
- Run single test: `python chat_logic_test.py` or `python provider-test.py --provider [provider_name] --prompt "Your test prompt"`

## Code Style Guidelines
- **Imports**: Standard library first, then third-party, then local modules
- **Naming**: snake_case for variables/functions, CamelCase for classes
- **Error Handling**: Use try/except with specific exception types, log errors appropriately
- **Architecture**: Follow the established pattern of provider abstraction through BaseLLMProvider
- **Configuration**: Use app/config.py for configuration management, reference .config.yml
- **Types**: Although not currently used, consider adding type hints for improved code clarity

## Project Structure
- `app/llm/`: LLM provider implementations (OpenAI, Ollama)
- `app/static/`, `app/templates/`: Frontend assets
- `app/chat_logic.py`: Core chat functionality
- `app/routes.py`: Flask routes for the web interface
- `data/`: Storage location for conversation data

## Scratchpad / Temp Files
- Use `temp/` for ephemeral notes (e.g., TODOs); it’s gitignored.

## Important Notes
- Always validate provider configurations before committing
- Test chat functionality with provider-test.py before making significant changes
- Use logging instead of print statements for debugging
