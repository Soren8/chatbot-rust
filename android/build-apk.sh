#!/usr/bin/env bash
# Build Chatbot Android APK with pinned JDK 21 (Capacitor / AGP requirement).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

FLAVOR="${1:-physical}"
# The first arg is the product flavor (build type is always Debug).
# Validate before any env checks so a typo fails fast anywhere with usage,
# instead of a confusing "Task 'assembleXxxDebug' not found" from Gradle.
if [[ "${FLAVOR}" == "-h" || "${FLAVOR}" == "--help" ]]; then
  echo "Usage: $(basename "$0") [emulator|physical] [gradle args...]" >&2
  exit 0
fi
if [[ "${FLAVOR}" != "emulator" && "${FLAVOR}" != "physical" ]]; then
  echo "ERROR: unknown flavor '${FLAVOR}'. Usage: $(basename "$0") [emulator|physical] [gradle args...]" >&2
  exit 2
fi

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

TASK="assemble$(tr '[:lower:]' '[:upper:]' <<< "${FLAVOR:0:1}")${FLAVOR:1}Debug"
exec ./gradlew "$TASK" "${@:2}"
