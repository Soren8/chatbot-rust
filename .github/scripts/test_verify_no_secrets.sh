#!/usr/bin/env bash
# Fixture regression test for verify_no_secrets.sh. The scanner matches
# `static` relative to the working directory, mirroring how CI invokes it
# from the repo root; each case therefore runs the scanner from a fixture
# root. Scanner path defaults to the sibling script, override with $1.
#
# Contract: the vendored SQL "authorization" keyword list and the known
# user-owned Connections DTO uses of `base_url` must PASS, while operator
# provider `base_url` configuration and every other original keyword
# (api_key, Bearer + space, OPENAI, OPENROUTER) still FAIL in first-party AND
# vendored paths. The real Authorization header shape (quoted/unquoted/mixed-
# case + colon) FAILS.
#
# All token-like values below are synthetic (TESTFIXTURE), never real secrets.
set -euo pipefail

SCANNER_IN="${1:-$(dirname "$0")/verify_no_secrets.sh}"
# Resolve once: cases cd into fixture roots, so the scanner path must be absolute.
SCANNER="$(cd "$(dirname "$SCANNER_IN")" && pwd)/$(basename "$SCANNER_IN")"
PASS=0
FAIL=0

new_root() {
  local root
  root="$(mktemp -d)"
  mkdir -p "$root/static/deps" "$root/static/templates"
  printf '%s' "$root"
}

check() {
  local name="$1" root="$2" expect="$3"
  local got
  if (cd "$root" && bash "$SCANNER" >/dev/null 2>&1); then
    got=0
  else
    got=1
  fi
  if [ "$got" = "$expect" ]; then
    echo "PASS: $name (exit $got)"
    PASS=$((PASS + 1))
  else
    echo "FAIL: $name (expected exit $expect, got $got)"
    FAIL=$((FAIL + 1))
  fi
  rm -rf "$root"
}

# --- Must pass: exact false-positive shape (vendored SQL keyword list) ---
R="$(new_root)"
cat > "$R/static/deps/vendor.min.js" <<'EOF'
const l=["abs","acos","alter","authorization","avg","begin"];
EOF
printf '%s\n' '// chat UI bootstrap, no secrets' 'window.APP="chat";' > "$R/static/app.js"
check "vendored SQL authorization keyword list passes" "$R" 0

# --- Must fail: preserved original keywords, first-party and vendored ---
R="$(new_root)"
printf '%s\n' '{{ llm.api_key }}' > "$R/static/templates/chat.html"
check "api_key first-party fails" "$R" 1

R="$(new_root)"
printf '%s\n' '// vendored bundle' 'var k="api_key";' > "$R/static/deps/bundle.min.js"
check "api_key vendored fails" "$R" 1

R="$(new_root)"
printf '%s\n' 'const u = cfg.base_url;' > "$R/static/app.js"
check "operator base_url setting in first-party asset fails" "$R" 1

R="$(new_root)"
cat > "$R/static/agent-connections.js" <<'EOF'
invalid_base_url: 'Enter a valid server-reachable URL.'
url.value = record.base_url;
details.textContent = record.name + record.base_url;
var payload = { name: name.value, base_url: url.value, username: username.value };
EOF
check "user-owned Connections metadata DTO fields pass" "$R" 0

R="$(new_root)"
cat > "$R/static/agent-connections.js" <<'EOF'
const headers = { Authorization: "Bearer TESTFIXTURE0123456789" };
const operatorKey = "OPENAI_API_KEY";
EOF
check "credential and auth markers in Connections asset still fail" "$R" 1

R="$(new_root)"
printf '%s\n' 'const provider = { base_url: operatorEndpoint };' > "$R/static/agent-connections.js"
check "operator provider base_url config in Connections asset fails" "$R" 1

R="$(new_root)"
printf '%s\n' 'const endpoint = record.base_url + provider.base_url;' > "$R/static/agent-connections.js"
check "operator base_url beside owned metadata on same line fails" "$R" 1

R="$(new_root)"
printf '%s\n' 'const provider = { base_url: operatorEndpoint };' > "$R/static/provider-settings.js"
check "operator base_url config elsewhere fails" "$R" 1

R="$(new_root)"
printf '%s\n' '// vendored bundle' 'var u="base_url";' > "$R/static/deps/bundle.min.js"
check "base_url vendored fails" "$R" 1

R="$(new_root)"
printf '%s\n' 'h.set("X-Test", "Bearer TESTFIXTURE0123456789");' > "$R/static/app.js"
check "Bearer first-party fails" "$R" 1

R="$(new_root)"
printf '%s\n' '// vendored bundle' 'var b="Bearer TESTFIXTURE0123456789";' > "$R/static/deps/bundle.min.js"
check "Bearer vendored fails" "$R" 1

R="$(new_root)"
printf '%s\n' '// uses OPENAI models' > "$R/static/app.js"
check "OPENAI first-party fails" "$R" 1

R="$(new_root)"
printf '%s\n' '// vendored bundle, OPENROUTER compatible' > "$R/static/deps/bundle.min.js"
check "OPENROUTER vendored fails" "$R" 1

# --- Must fail: real Authorization header shape, quoted/unquoted/mixed-case,
# --- plus whitespace before colon. Values use the Basic scheme (synthetic)
# --- so only the Authorization branch can match (no Bearer/api_key/etc). ---
R="$(new_root)"
printf '%s\n' 'headers: { "Authorization": "Basic TESTFIXTURE0123456789" }' > "$R/static/app.js"
check "quoted Authorization header fails" "$R" 1

R="$(new_root)"
printf '%s\n' 'headers: { Authorization: "Basic TESTFIXTURE0123456789" }' > "$R/static/app.js"
check "unquoted Authorization header fails" "$R" 1

R="$(new_root)"
printf '%s\n' 'headers: { "aUtHoRiZaTiOn": "Basic TESTFIXTURE0123456789" }' > "$R/static/app.js"
check "mixed-case Authorization header fails" "$R" 1

R="$(new_root)"
printf '%s\n' 'headers: { "Authorization" : "Basic TESTFIXTURE0123456789" }' > "$R/static/app.js"
check "whitespace-before-colon Authorization header fails" "$R" 1

echo "---"
echo "pass=$PASS fail=$FAIL"
[ "$FAIL" -eq 0 ]
