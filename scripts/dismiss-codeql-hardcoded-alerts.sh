#!/usr/bin/env bash
# Bulk-dismiss open CodeQL alerts for rust/hard-coded-cryptographic-value
# (false positives from test fixtures / form defaults). Requires `gh` auth.
#
# Usage (from repo root, with push access):
#   ./scripts/dismiss-codeql-hardcoded-alerts.sh
set -euo pipefail

RULE_ID="${RULE_ID:-rust/hard-coded-cryptographic-value}"
REASON="${REASON:-false positive}"
COMMENT="${COMMENT:-Test fixtures / empty form defaults; query excluded in .github/codeql/codeql-config.yml}"

command -v gh >/dev/null 2>&1 || {
  echo "error: gh (GitHub CLI) is required" >&2
  exit 1
}

repo="$(gh repo view --json nameWithOwner -q .nameWithOwner)"
echo "Dismissing open alerts for ${RULE_ID} on ${repo}..."

mapfile -t numbers < <(
  gh api --paginate "repos/${repo}/code-scanning/alerts" \
    --jq ".[] | select(.state==\"open\" and .rule.id==\"${RULE_ID}\") | .number"
)

if [[ ${#numbers[@]} -eq 0 ]]; then
  echo "No open alerts for ${RULE_ID}."
  exit 0
fi

echo "Found ${#numbers[@]} alert(s)."
for n in "${numbers[@]}"; do
  gh api --method PATCH "repos/${repo}/code-scanning/alerts/${n}" \
    -f state=dismissed \
    -f dismissed_reason="${REASON}" \
    -f dismissed_comment="${COMMENT}" \
    --silent
  echo "  dismissed #${n}"
done
echo "Done."
