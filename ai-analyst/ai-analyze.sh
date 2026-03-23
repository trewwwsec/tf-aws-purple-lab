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

ALERT_ID="$(
python3 - "${PAYLOAD_FILE}" <<'PY'
import json
import sys

def dig(obj, keys):
    cur = obj
    for key in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    payload = json.load(f)

candidates = [
    ("parameters", "alert", "id"),
    ("alert", "id"),
    ("id",),
]

for keys in candidates:
    value = dig(payload, keys)
    if value not in (None, ""):
        print(str(value))
        raise SystemExit(0)

print("")
PY
)"

if [[ -n "${ALERT_ID}" ]]; then
  exec python3 "${ANALYZE_SCRIPT}" --alert-id "${ALERT_ID}" --output json --mode "${RUNTIME_MODE}"
fi

exec python3 "${ANALYZE_SCRIPT}" --alert-file "${PAYLOAD_FILE}" --output json --mode "${RUNTIME_MODE}"
