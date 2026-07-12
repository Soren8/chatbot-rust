#!/usr/bin/env bash
# Bulk-dismiss open CodeQL hard-coded-crypto alerts that only fire in tests.
# Production alerts for the same rule are left alone. Requires `gh` auth.
#
# Usage (from repo root, with push access):
#   ./scripts/dismiss-codeql-hardcoded-alerts.sh
set -euo pipefail

RULE_ID="${RULE_ID:-rust/hard-coded-cryptographic-value}"
REASON="${REASON:-false positive}"
COMMENT="${COMMENT:-Test fixture; **/tests/** excluded from CodeQL via .github/codeql/codeql-config.yml}"

command -v gh >/dev/null 2>&1 || {
  echo "error: gh (GitHub CLI) is required" >&2
  exit 1
}

repo="$(gh repo view --json nameWithOwner -q .nameWithOwner)"
echo "Dismissing open ${RULE_ID} alerts under tests/ on ${repo}..."

# Match common Rust/integration test locations only.
is_test_path() {
  local p="$1"
  [[ "$p" == */tests/* ]] \
    || [[ "$p" == */test_*.rs ]] \
    || [[ "$p" == *_test.rs ]] \
    || [[ "$p" == */tests.rs ]]
}

mapfile -t numbers < <(
  gh api --paginate "repos/${repo}/code-scanning/alerts" \
    --jq --arg rule "$RULE_ID" '
      .[]
      | select(.state=="open" and .rule.id==$rule)
      | select(
          (.most_recent_instance.location.path // .most_recent_instance.location.file // "")
          | test("(^|/)tests/|/test_[^/]+\\.rs$|_test\\.rs$|/tests\\.rs$")
        )
      | .number
    '
)

if [[ ${#numbers[@]} -eq 0 ]]; then
  echo "No open test-path alerts for ${RULE_ID}."
  exit 0
fi

echo "Found ${#numbers[@]} test-path alert(s)."
for n in "${numbers[@]}"; do
  gh api --method PATCH "repos/${repo}/code-scanning/alerts/${n}" \
    -f state=dismissed \
    -f dismissed_reason="${REASON}" \
    -f dismissed_comment="${COMMENT}" \
    --silent
  echo "  dismissed #${n}"
done
echo "Done. Production alerts for ${RULE_ID} (if any) were not touched."
