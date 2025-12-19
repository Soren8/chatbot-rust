# Chatbot Rust

This repository hosts a containerized Rust-based chatbot web application with a clean, responsive Bootstrap frontend. It runs a high-performance Axum-based HTTP server, supports pluggable local or remote LLM and TTS APIs, and manages chat history and sessions encrypted securely on disk. See design-privacy.md for details on storage privacy.

It started off as a simple single-threaded Flask app to test out vibe coding, but has been refactored into concurrent Rust with test coverage and security hardening as tools have improved.

Not a single line of code in this repository was written manually. Human work included: model/agent selections, design guidance, code review, testing, bug reporting, small edits, etc.

## Features
- Axum server with configurable CSRF-protected routes (enabled by default) for chat, authentication, set management, and TTS.
- `chatbot-core` crate encapsulating chat logic, provider abstractions, persistence, and session management.
- Static assets rendered with Minijinja and served from `static/`.
- Async provider implementations (OpenAI, Ollama) with streaming support and configurable defaults.
- Comprehensive integration tests (`cargo test`) covering routes, session flows, and external service stubs.

## Repository Layout
- `chatbot-core/` – core business logic, configuration, providers, persistence, and session manager.
- `chatbot-server/` – Axum HTTP server, route handlers, middleware, and integration tests.
- `chatbot-test-support/` – shared fixtures and helpers for integration tests.
- `data/` – gitignored persistence for chats, sessions, and users.
- `static/` – static assets and Minijinja templates.
- `docs/` – design and privacy documentation.
- `temp/` – gitignored caches and scratch space (`temp/.cargo`, `temp/.docker`, `temp/test-logs`).

## Prerequisites
- Docker and Docker Compose.
- A `.config.yml` (use `.config.yml.example` as a starting point) with provider credentials and runtime settings.
- Any LLM/TTS endpoints referenced in the configuration should be reachable from the containers.

## Development Workflow
1. Copy `.config.yml.example` to `.config.yml` and adjust provider settings.
1. Add API keys to environment variables or copy `.env.example` to `.env` and adjust.
1. Run the integration and unit tests:
   ```bash
   docker compose run --rm tests cargo test
   ```
1. Build the runtime image and start services:
   ```bash
   docker compose up --build
   ```
   RUST_BUILD_TARGET=debug by default, you may want to set it to release.
1. Keep caches under `temp/` as described in `AGENTS.md`.

## Configuration
- Provider and environment settings live in `.config.yml`; secrets should be injected through environment variables where possible.
- Environment variables from `.env`/`.env.example` are consumed by Docker Compose for development defaults.

## Documentation
- Overview and roadmap: `docs/design.md`
- Privacy posture and data handling guidelines: `docs/design-privacy.md`

## Contributing
- Follow the guidelines in `AGENTS.md` for coding style, testing strategy, and cache usage.
- Add or update integration tests before modifying core features.
- Run the Dockerized test suite and update relevant documentation before opening a pull request.
- Vibe Pull Requests welcome. We love AI here.