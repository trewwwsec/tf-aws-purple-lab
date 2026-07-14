#!/usr/bin/env bash
# Wazuh active-response hook entry-point: analyzes alert payload from stdin.
# The payload is expected to be a raw Wazuh alert JSON or an active-response
# wrapper containing the alert at `alert` or `parameters.alert`.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANALYZE_SCRIPT="${SCRIPT_DIR}/src/analyze_alert.py"
RUNTIME_MODE="${AI_ANALYST_MODE:-strict}"

if [[ ! -f "${ANALYZE_SCRIPT}" ]]; then
  echo "analyze_alert.py not found at ${ANALYZE_SCRIPT}" >&2
  exit 1
fi

# Validate stdin is not a TTY (should be piped from active-response hook)
if [[ -t 0 ]]; then
  echo "No data on stdin. This script is meant to be called by a Wazuh active-response hook." >&2
  exit 1
fi

exec python3 "${ANALYZE_SCRIPT}" --stdin --output json --mode "${RUNTIME_MODE}"
