# chatbot Helm chart (sample)

Minimal sample chart for the Rust **webserver** image. The GPU **voice-service** is disabled by default (`voiceService.enabled: false`) because it typically runs on host networking with NVIDIA devices — mirror your Compose layout or run voice on bare metal.

## Sample-only values (unsupported)

- `voiceService.enabled` is accepted but has **no effect**: no template under `templates/` reads `.Values.voiceService` and there is no voice-service Deployment. It exists only to document the intended topology. Run voice-service on the GPU host / bare metal and point `voice_service_host` in the ConfigMap at it.
- `stt_enabled` (root `.config.yml`) is parsed by the webserver config but the `/stt` route does **not** gate on it — STT always proxies to the voice service when reached. Documented here only; no runtime change in this sample.

## Install

Build/push images first (or use local tags with a kind/minikube load):

```bash
docker compose build webserver
# tag & push chatbot-rust:your-tag
```

```bash
helm install chatbot deploy/helm/chatbot \
  --set webserver.secretEnv.SECRET_KEY='your-secret' \
  --set webserver.image.tag=your-tag
```

## Host networking (default)

`webserver.hostNetwork: true` matches root `docker-compose.yml` so the webserver can reach `voice-service` on `127.0.0.1:5100`. For cluster-internal networking, set `hostNetwork: false` and point `voice_service_host` in the ConfigMap at your voice Service DNS name.

## Probes

- Liveness: `GET /health`
- Readiness: `GET /health?deep=true` (redb + voice-service)

## Persistence

When `webserver.persistence.enabled` is true, chat history and user data mount at `/app/data`.