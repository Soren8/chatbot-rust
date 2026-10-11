# chatbot Helm chart (sample)

Minimal sample chart for the Rust **webserver** image. The GPU **voice-service** is disabled by default (`voiceService.enabled: false`); unlike Compose, this chart does not deploy voice, so run it separately and configure its reachable address.

## Sample-only values (unsupported)

- `voiceService.enabled` is accepted but has **no effect**: no template under `templates/` reads `.Values.voiceService` and there is no voice-service Deployment. It exists only to document the intended topology. Run the standalone chatbot-voice service on the GPU host / bare metal (or a hosted OpenAI-compatible provider) and point the `tts:`/`stt:` blocks in the ConfigMap at it.
- `stt_enabled` is a removed `.config.yml` key and the webserver refuses it; the `/stt` route always proxies to the `stt:` block's OpenAI-compatible `/audio/transcriptions` endpoint.

## Install

Build/push images first (or use local tags with a kind/minikube load):

```bash
docker compose build webserver
# tag & push chatbot-rust:your-tag
```

```bash
helm install chatbot deploy/helm/chatbot \
  --set webserver.secretEnv.SECRET_KEY.name=chatbot-secrets \
  --set webserver.secretEnv.SECRET_KEY.key=SECRET_KEY \
  --set webserver.image.tag=your-tag
```

Create `chatbot-secrets` separately (for example via Sealed Secrets or External Secrets) before installing. `webserver.secretEnv` accepts only `{name, key}` references to existing Kubernetes Secrets; unset entries are omitted and nonempty literal values fail template rendering. Do not pass secret values via Helm `--set` or values files.

## Host networking (default)

`webserver.hostNetwork: true` is a chart-only default (Compose uses a bridge). Point the ConfigMap's `tts.base_url`/`stt.base_url` at a reachable endpoint, or set `hostNetwork: false` and use a cluster voice Service DNS name.

## Probes

- Liveness: `GET /health`
- Readiness: `GET /health?deep=true` (redb + configured voice `health_url`s)

## Persistence

When `webserver.persistence.enabled` is true, chat history and user data mount at `/app/data`.
