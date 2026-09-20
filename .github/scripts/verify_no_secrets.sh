#!/usr/bin/env bash
set -euo pipefail

# Match Authorization header syntax, not the SQL keyword in highlight.js.
echo "Scanning templates and static assets for potential secrets..."
if grep -RinE "api_key|['\"]?Authorization['\"]?[[:space:]]*:|Bearer |OPENAI|OPENROUTER|base_url" static ; then
  echo "Error: potential secret token detected in served assets." >&2
  exit 1
fi
echo "OK: no secret tokens found in served assets."
