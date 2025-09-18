# AGENTS.md - Development Guide

## Build & Run Commands
- Start app (dev): `flask run` or `python -m app`
- Run in Docker: `docker compose up --build`
- Run single test: `python chat_logic_test.py` or `python provider-test.py --provider [provider_name] --prompt "Your test prompt"`
- Run tests in Docker: `docker compose up --build --exit-code-from tests tests` (reuses the app image with a test target)

## Code Style Guidelines
- **Imports**: Standard library first, then third-party, then local modules
- **Naming**: snake_case for variables/functions, CamelCase for classes
- **Error Handling**: Use try/except with specific exception types, log errors appropriately
- **Architecture**: Follow the established pattern of provider abstraction through BaseLLMProvider
- **Configuration**: Use app/config.py for configuration management, reference .config.yml
- **Types**: Although not currently used, consider adding type hints for improved code clarity
- **Dead code**: Prefer deleting unused code over commenting it out
- **History**: Do not add comments about how code used to be; use git history

## Project Structure
- `app/llm/`: LLM provider implementations (OpenAI, Ollama)
- `app/static/`, `app/templates/`: Frontend assets
- `app/chat_logic.py`: Core chat functionality
- `app/routes.py`: Flask routes for the web interface
- `data/`: Storage location for conversation data

## Scratchpad / Temp Files
- Use `temp/` for ephemeral notes (e.g., TODOs) — it is gitignored
- Never reference `temp/` items in commit messages
- Keep `temp/todo.md` updated as you progress

## Important Notes
- Before starting work, read `design.md` and `design-privacy.md` to align with the current architecture and privacy posture. Follow any in-progress refactor trail they reference (currently `docs/rust-refactor.md`).
- At session start, ask if the user wants frequent commits; default to frequent if unspecified.
- Do not moralize about the user's language or tone.
- Always validate provider configurations before committing
- Test chat functionality with provider-test.py before making significant changes
- Use logging instead of print statements for debugging
- Skip running `python3 -m compileall`; it’s slow here and the user will run real functional tests.
