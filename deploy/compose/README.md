# Compose deployment samples

These files are **overrides** for the root [`docker-compose.yml`](../../docker-compose.yml). They do not run standalone.

## Production-style

```bash
docker compose \
  -f docker-compose.yml \
  -f deploy/compose/docker-compose.prod.override.yml \
  up -d --build
```

- Release Rust build
- JSON logs (`LOG_FORMAT=json`, `LOG_ANSI=false`)
- Webserver waits for voice-service health

## Development

```bash
docker compose \
  -f docker-compose.yml \
  -f deploy/compose/docker-compose.dev.override.yml \
  up --build
```

- Debug Rust build
- Plain logs, shorter background session purge interval

## Environment

Secrets and `SECRET_KEY` still come from the host `.env` consumed by Compose. Data persists under `./data` (webserver) and `./chatbot-cuda/data` (voice).