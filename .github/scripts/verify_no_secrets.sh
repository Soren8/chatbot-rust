#!/usr/bin/env bash
set -euo pipefail

echo "Scanning templates and static assets for potential secrets..."
if grep -RinE "api_key|['\"]?Authorization['\"]?[[:space:]]*:|Bearer |OPENAI|OPENROUTER" static ; then
  echo "Error: potential secret token detected in served assets." >&2
  exit 1
fi

# `base_url` is also the intentionally exposed field name of a user's own
# encrypted agent connection. Allow only the metadata uses in that UI; keep
# rejecting provider/operator endpoint configuration everywhere else. This is
# line-level text matching, not a JavaScript parser, and does not exempt the
# asset from the credential/header scans above.
if grep -RinE 'base_url' static | awk -F: '
  {
    path = $1
    raw = $0
    line = $0
    sub(/^[^:]*:[0-9]+:/, "", raw)
    line = tolower(raw)
    if (path == "static/agent-connections.js") {
      gsub(/invalid_base_url:/, "", line)
      gsub(/record[.]base_url/, "", line)
      gsub(/base_url:[[:space:]]*url[.]value/, "", line)
    }
    if (line ~ /base_url/) {
      print $0
      found = 1
    }
  }
  END { exit !found }
'; then
  echo "Error: unexpected base_url configuration in served assets." >&2
  exit 1
fi

echo "OK: no secret tokens found in served assets."
