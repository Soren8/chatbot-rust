#!/usr/bin/env bash
# Build Chatbot Android APK with pinned JDK 21 (Capacitor / AGP requirement).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ -z "${JAVA_HOME:-}" ]]; then
  for candidate in \
    /usr/lib/jvm/java-21-openjdk-amd64 \
    /usr/lib/jvm/java-21-openjdk \
    /usr/lib/jvm/default-java
  do
    if [[ -d "$candidate" && -x "$candidate/bin/java" ]]; then
      export JAVA_HOME="$candidate"
      break
    fi
  done
fi

if [[ -z "${JAVA_HOME:-}" || ! -x "${JAVA_HOME}/bin/java" ]]; then
  echo "ERROR: JDK 21 required. Set JAVA_HOME to a Java 21 installation." >&2
  exit 1
fi

JAVA_VER="$("${JAVA_HOME}/bin/java" -version 2>&1 | head -1)"
echo "[build-apk] JAVA_HOME=${JAVA_HOME}"
echo "[build-apk] ${JAVA_VER}"

if [[ -z "${ANDROID_HOME:-}" && -d "${HOME}/Android/Sdk" ]]; then
  export ANDROID_HOME="${HOME}/Android/Sdk"
fi

FLAVOR="${1:-production}"
TASK="assemble$(tr '[:lower:]' '[:upper:]' <<< "${FLAVOR:0:1}")${FLAVOR:1}Debug"
exec ./gradlew "$TASK" "${@:2}"
