# Chatbot Rust

This repository hosts a containerized Rust-based chatbot web application with a clean, responsive Bootstrap frontend. It runs a high-performance Axum-based HTTP server, supports pluggable local or remote LLM and TTS APIs, stores encrypted chat history on disk, and keeps sessions in memory. Remember tokens are stored as hashes. See design-privacy.md for details on storage privacy.

It started off as a simple single-threaded Flask app to test out vibe coding, but has been refactored into concurrent Rust with test coverage and security hardening as tools have improved.

Not a single line of code in this repository was written manually. Human work included: model/agent selections, design guidance, code review, testing, bug reporting, small edits, etc.

## Features
- Axum server with configurable CSRF-protected routes (enabled by default) for chat, authentication, set management, and TTS.
- Browser TTS via `POST /tts` → `GET /tts_stream/{token}` only; access gated by deploy config `tts_access` (`anyone` | `authenticated` | `premium`).
- `chatbot-core` crate encapsulating chat logic, config, history (redb), persistence helpers, and session management.
- Static assets rendered with Minijinja and served from `static/`.
- Async provider implementations (OpenAI-compatible, XAI) in `chatbot-server` with streaming support and configurable defaults.
- Comprehensive integration tests run in the Docker test image (`docker compose run --rm tests`; agents use `testctl` per [AGENTS.md](AGENTS.md)) covering routes, session flows, and external service stubs.

## Repository Layout
- `chatbot-core/` – core business logic, configuration, history store (redb), permanent `legacy_sets_json` migration, Fernet helpers, and session manager.
- `chatbot-server/` – Axum HTTP server, route handlers, LLM/TTS providers, middleware, and integration tests.
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
   Set `voice_service_host: localhost` in existing configs; the bridge voice service publishes only `127.0.0.1:5100`. The host-networked webserver uses `localhost` for host-based providers, not `host.docker.internal`.
1. Add API keys to environment variables or copy `.env.example` to `.env` and adjust.
1. Run the integration and unit tests:
   ```bash
   docker compose up -d --build dns
   docker compose run --rm tests
   ```
1. Build the runtime image and start services:
   ```bash
   docker compose up --build
   ```
   Webserver uses host networking and listens directly on port 80 by default; `CHATBOT_BIND_ADDR` controls the host listener (with `CHATBOT_PORT` as its default port). DNS, voice-service and tests remain on the Compose bridge. Webserver mounts `dns/host-resolv.conf` read-only to use the DNS sidecar. If `172.29.0.0/16` overlaps your network, set `DNS_SUBNET` and `DNS_ADDRESS` together, recreate the Compose default network, and set `WEB_RESOLV_CONF` to a host resolver file containing `nameserver <DNS_ADDRESS>`; Compose cannot substitute variables inside that file.
   RUST_BUILD_TARGET=debug by default, you may want to set it to release.
1. Keep caches under `temp/` as described in `AGENTS.md`.

**Secure context for browser dev (encryption keys):** Client-side key derivation and storage (required for Private Mode chat data) needs a browser secure context. Use `http://localhost` or https (recommended for LAN: run Tailscale Serve on the host pointing at the app, e.g. proxying to the host listener). Plain http://LAN-IP will cause login to fall back to server derivation and subsequent data operations to require unlock that cannot succeed in-browser. The native Android app works over HTTP using its NativeSecureKey plugin.

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
