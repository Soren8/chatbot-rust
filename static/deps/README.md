# Vendored front-end libraries

First-party UI loads these from `/static/deps/` (no CDN). VAD files live in `vad/` with their own `VERSION`.

| Library | Version | License | Upstream |
|---|---|---|---|
| jquery | 3.6.0 | MIT | https://code.jquery.com/jquery-3.6.0.min.js |
| bootstrap (css + bundle js) | 5.3.0 | MIT | https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/ |
| bootstrap-icons (css + woff/woff2) | 1.10.5 | MIT | https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/ |
| marked | 15.0.7 | MIT | https://cdn.jsdelivr.net/npm/marked@15.0.7/marked.min.js |
| highlight.js (js + github-dark css) | 11.9.0 | BSD-3-Clause | https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js |

Vendored 2026-09-01. Pin and vendor locally so CSP can stay `'self'`.
