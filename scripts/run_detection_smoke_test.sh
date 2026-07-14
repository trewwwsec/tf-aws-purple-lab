#!/bin/bash
# =============================================================================
# Run Detection Smoke Test
# Cloud SOC Platform
# =============================================================================
#
# PURPOSE:
#   Convenience wrapper around scripts/smoke_test_detections.py that
#   auto-discovers the deployed Wazuh server IP and SSH key from Terraform.
#
# USAGE:
#   ./scripts/run_detection_smoke_test.sh --simulation privilege-escalation
#   ./scripts/run_detection_smoke_test.sh --simulation ssh-brute-force --mode api
#   ./scripts/run_detection_smoke_test.sh --rule-id 200001 --rule-id 200021
#
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TERRAFORM_DIR="$PROJECT_ROOT/terraform"
SMOKE_TEST_SCRIPT="$SCRIPT_DIR/smoke_test_detections.py"

MODE="ssh-log"
SIMULATION=""
TIMEOUT=""
POLL_INTERVAL=""
FRESH_WINDOW=""
SSH_TARGET=""
SSH_KEY=""
RULE_IDS=()
PASSTHROUGH_ARGS=()

print_help() {
    cat << EOF
Run Detection Smoke Test

Usage:
  ./scripts/run_detection_smoke_test.sh [options]

Options:
  --simulation <name>     Known simulation name (for example: privilege-escalation)
  --rule-id <id>          Expected custom rule ID (repeatable)
  --mode <api|ssh-log>    Validation mode (default: ssh-log)
  --timeout <seconds>     Wait timeout passed to smoke test
  --poll-interval <sec>   Poll interval for API mode
  --fresh-window <sec>    Freshness window for API mode
  --ssh-target <target>   Override SSH target (default: auto-detect from Terraform)
  --ssh-key <path>        Override SSH private key path (default: auto-detect from tfvars)
  --list-simulations      Show known simulation names
  --help                  Show this help

Examples:
  ./scripts/run_detection_smoke_test.sh --simulation privilege-escalation
  ./scripts/run_detection_smoke_test.sh --simulation ssh-brute-force --timeout 240
  ./scripts/run_detection_smoke_test.sh --simulation privilege-escalation --mode api
EOF
}

fail() {
    echo "ERROR: $1" >&2
    exit 1
}

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        fail "$1 is required but not installed."
    fi
}

discover_wazuh_ip() {
    require_command terraform

    if [ ! -d "$TERRAFORM_DIR/.terraform" ]; then
        fail "Terraform is not initialized in $TERRAFORM_DIR. Run terraform init or pass --ssh-target manually."
    fi

    local ip
    ip=$(cd "$TERRAFORM_DIR" && terraform output -raw wazuh_server_public_ip 2>/dev/null) || true
    [ -n "$ip" ] || fail "Could not determine wazuh_server_public_ip from Terraform outputs."
    echo "$ip"
}

discover_ssh_key() {
    local tfvars_file="$TERRAFORM_DIR/terraform.tfvars"
    local detected=""

    if [ -f "$tfvars_file" ]; then
        detected=$(grep -oE 'ssh_private_key_path[[:space:]]*=[[:space:]]*"[^"]+"' "$tfvars_file" \
            | sed 's/.*"\(.*\)"/\1/' | head -1) || true
    fi

    if [ -z "$detected" ]; then
        for candidate in "$HOME/.ssh/cloud-soc-key.pem" "$HOME/.ssh/cloud-soc-key"; do
            if [ -f "$candidate" ]; then
                detected="$candidate"
                break
            fi
        done
    fi

    detected="${detected/#\~/$HOME}"
    [ -n "$detected" ] || fail "Could not determine SSH private key. Pass --ssh-key explicitly."
    [ -f "$detected" ] || fail "SSH private key not found at $detected."
    echo "$detected"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --simulation)
            SIMULATION="${2:-}"
            shift 2
            ;;
        --rule-id)
            RULE_IDS+=("${2:-}")
            shift 2
            ;;
        --mode)
            MODE="${2:-}"
            shift 2
            ;;
        --timeout)
            TIMEOUT="${2:-}"
            shift 2
            ;;
        --poll-interval)
            POLL_INTERVAL="${2:-}"
            shift 2
            ;;
        --fresh-window)
            FRESH_WINDOW="${2:-}"
            shift 2
            ;;
        --ssh-target)
            SSH_TARGET="${2:-}"
            shift 2
            ;;
        --ssh-key)
            SSH_KEY="${2:-}"
            shift 2
            ;;
        --list-simulations)
            PASSTHROUGH_ARGS+=("--list-simulations")
            shift
            ;;
        --help|-h)
            print_help
            exit 0
            ;;
        *)
            fail "Unknown argument: $1"
            ;;
    esac
done

require_command python3

if [ ${#PASSTHROUGH_ARGS[@]} -gt 0 ]; then
    exec python3 "$SMOKE_TEST_SCRIPT" "${PASSTHROUGH_ARGS[@]}"
fi

if [ -z "$SIMULATION" ] && [ ${#RULE_IDS[@]} -eq 0 ]; then
    fail "Provide --simulation or at least one --rule-id."
fi

CMD=(python3 "$SMOKE_TEST_SCRIPT" --mode "$MODE")

if [ -n "$SIMULATION" ]; then
    CMD+=(--simulation "$SIMULATION")
fi

for rule_id in "${RULE_IDS[@]}"; do
    CMD+=(--rule-id "$rule_id")
done

if [ -n "$TIMEOUT" ]; then
    CMD+=(--timeout "$TIMEOUT")
fi

if [ -n "$POLL_INTERVAL" ]; then
    CMD+=(--poll-interval "$POLL_INTERVAL")
fi

if [ -n "$FRESH_WINDOW" ]; then
    CMD+=(--fresh-window-seconds "$FRESH_WINDOW")
fi

if [ "$MODE" = "ssh-log" ]; then
    if [ -z "$SSH_TARGET" ]; then
        SSH_TARGET="ubuntu@$(discover_wazuh_ip)"
    fi
    if [ -z "$SSH_KEY" ]; then
        SSH_KEY="$(discover_ssh_key)"
    else
        SSH_KEY="${SSH_KEY/#\~/$HOME}"
    fi
    CMD+=(--ssh-target "$SSH_TARGET" --ssh-key "$SSH_KEY")
    echo "Using ssh-log mode against $SSH_TARGET"
    echo "Using SSH key $SSH_KEY"
else
    echo "Using api mode. Ensure WAZUH_HOST/WAZUH_USER/WAZUH_PASSWORD are set."
fi

exec "${CMD[@]}"
