#!/usr/bin/env bash
set -euo pipefail

echo "Scanning templates and static assets for potential secrets..."
if grep -RinE "api_key|Authorization|Bearer |OPENAI|OPENROUTER|base_url" static ; then
  echo "Error: potential secret token detected in served assets." >&2
  exit 1
fi
echo "OK: no secret tokens found in served assets."
