#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANALYZE_SCRIPT="${SCRIPT_DIR}/src/analyze_alert.py"
RUNTIME_MODE="${AI_ANALYST_MODE:-strict}"

if [[ ! -f "${ANALYZE_SCRIPT}" ]]; then
  echo "analyze_alert.py not found at ${ANALYZE_SCRIPT}" >&2
  exit 1
fi

PAYLOAD_FILE="$(mktemp /tmp/ai-analyze.XXXXXX.json)"
trap 'rm -f "${PAYLOAD_FILE}"' EXIT

cat > "${PAYLOAD_FILE}"

if [[ ! -s "${PAYLOAD_FILE}" ]]; then
  echo "Empty active response payload" >&2
  exit 1
fi

exec python3 "${ANALYZE_SCRIPT}" --alert-file "${PAYLOAD_FILE}" --output json --mode "${RUNTIME_MODE}"
