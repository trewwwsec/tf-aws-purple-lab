#!/bin/bash
# =============================================================================
# Run End-to-End Detection Test
# Cloud SOC Platform
# =============================================================================
#
# PURPOSE:
#   Execute a safe attack simulation on the Linux endpoint, then validate the
#   expected detections on the Wazuh server using the smoke-test helper.
#
# CURRENT SCOPE:
#   - privilege-escalation (Linux endpoint)
#   - ssh-brute-force (Linux endpoint, localhost password-auth flow)
#
# USAGE:
#   ./scripts/run_end_to_end_detection_test.sh --simulation privilege-escalation
#   ./scripts/run_end_to_end_detection_test.sh --simulation ssh-brute-force --timeout 300
#
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TERRAFORM_DIR="$PROJECT_ROOT/terraform"
SMOKE_WRAPPER="$SCRIPT_DIR/run_detection_smoke_test.sh"

SIMULATION=""
TIMEOUT=240
SSH_KEY=""
WAZUH_IP=""
LINUX_IP=""
E2E_SSH_USER="socbrute$$"
E2E_SSH_PASSWORD="SocTemp!234$$"

print_help() {
    cat << EOF
Run End-to-End Detection Test

Usage:
  ./scripts/run_end_to_end_detection_test.sh --simulation <name> [options]

Options:
  --simulation <name>    Supported: privilege-escalation, ssh-brute-force
  --timeout <seconds>    Smoke-test timeout after simulation starts (default: 240)
  --ssh-key <path>       Override SSH private key path
  --wazuh-ip <ip>        Override Wazuh server public IP
  --linux-ip <ip>        Override Linux endpoint private IP
  --help                 Show this help

Example:
  ./scripts/run_end_to_end_detection_test.sh --simulation privilege-escalation
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

discover_tf_output() {
    local output_name="$1"
    require_command terraform
    if [ ! -d "$TERRAFORM_DIR/.terraform" ]; then
        fail "Terraform is not initialized in $TERRAFORM_DIR."
    fi
    local value
    value=$(cd "$TERRAFORM_DIR" && terraform output -raw "$output_name" 2>/dev/null) || true
    [ -n "$value" ] || fail "Could not determine Terraform output: $output_name"
    echo "$value"
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

run_remote() {
    local remote_cmd="$1"
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -i "$SSH_KEY" -J "ubuntu@$WAZUH_IP" "$REMOTE_USER_HOST" \
        "$remote_cmd"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --simulation)
            SIMULATION="${2:-}"
            shift 2
            ;;
        --timeout)
            TIMEOUT="${2:-}"
            shift 2
            ;;
        --ssh-key)
            SSH_KEY="${2:-}"
            shift 2
            ;;
        --wazuh-ip)
            WAZUH_IP="${2:-}"
            shift 2
            ;;
        --linux-ip)
            LINUX_IP="${2:-}"
            shift 2
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

case "$SIMULATION" in
    privilege-escalation)
        SIMULATION_SCRIPT="privilege-escalation.sh"
        SMOKE_RULE_IDS=(200020 200021 200022 200032)
        REMOTE_ENV=""
        PREP_COMMAND="true"
        RESTORE_COMMAND="true"
        ;;
    ssh-brute-force)
        SIMULATION_SCRIPT="ssh-brute-force.sh"
        SMOKE_RULE_IDS=(200001 200002)
        PREP_COMMAND=$(cat <<'EOF'
set -euo pipefail
sudo apt-get update -y >/dev/null
sudo apt-get install -y openssh-server sshpass >/dev/null
sudo systemctl enable ssh >/dev/null 2>&1 || true
sudo systemctl restart ssh >/dev/null 2>&1 || sudo systemctl restart sshd >/dev/null 2>&1 || true
BACKUP_FILE="$REMOTE_BASE/sshd_config.backup"
sudo cp /etc/ssh/sshd_config "$BACKUP_FILE"
if sudo grep -qE '^[#[:space:]]*PasswordAuthentication[[:space:]]+' /etc/ssh/sshd_config; then
  sudo sed -i 's/^[#[:space:]]*PasswordAuthentication[[:space:]].*/PasswordAuthentication yes/' /etc/ssh/sshd_config
else
  echo 'PasswordAuthentication yes' | sudo tee -a /etc/ssh/sshd_config >/dev/null
fi
if sudo grep -qE '^[#[:space:]]*KbdInteractiveAuthentication[[:space:]]+' /etc/ssh/sshd_config; then
  sudo sed -i 's/^[#[:space:]]*KbdInteractiveAuthentication[[:space:]].*/KbdInteractiveAuthentication yes/' /etc/ssh/sshd_config
fi
if sudo grep -qE '^[#[:space:]]*ChallengeResponseAuthentication[[:space:]]+' /etc/ssh/sshd_config; then
  sudo sed -i 's/^[#[:space:]]*ChallengeResponseAuthentication[[:space:]].*/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config
fi
sudo systemctl restart ssh >/dev/null 2>&1 || sudo systemctl restart sshd >/dev/null 2>&1
sudo useradd -m "$E2E_SSH_USER" >/dev/null 2>&1 || true
echo "${E2E_SSH_USER}:${E2E_SSH_PASSWORD}" | sudo chpasswd
EOF
)
        RESTORE_COMMAND=$(cat <<'EOF'
set -euo pipefail
if [ -f "$REMOTE_BASE/sshd_config.backup" ]; then
  sudo cp "$REMOTE_BASE/sshd_config.backup" /etc/ssh/sshd_config
  sudo systemctl restart ssh >/dev/null 2>&1 || sudo systemctl restart sshd >/dev/null 2>&1 || true
fi
sudo userdel -r "$E2E_SSH_USER" >/dev/null 2>&1 || sudo userdel "$E2E_SSH_USER" >/dev/null 2>&1 || true
EOF
)
        REMOTE_ENV="export SSH_TARGET_HOST=127.0.0.1 SSH_TARGET_USER='$E2E_SSH_USER' SSH_VALID_PASSWORD='$E2E_SSH_PASSWORD'; "
        ;;
    "")
        fail "Provide --simulation."
        ;;
    *)
        fail "Unsupported simulation: $SIMULATION. Supported: privilege-escalation, ssh-brute-force"
        ;;
esac

require_command bash
require_command ssh
require_command scp

if [ -z "$WAZUH_IP" ]; then
    WAZUH_IP="$(discover_tf_output wazuh_server_public_ip)"
fi

if [ -z "$LINUX_IP" ]; then
    LINUX_IP="$(discover_tf_output linux_endpoint_private_ip)"
fi

if [ -z "$SSH_KEY" ]; then
    SSH_KEY="$(discover_ssh_key)"
else
    SSH_KEY="${SSH_KEY/#\~/$HOME}"
fi

[ -f "$SSH_KEY" ] || fail "SSH private key not found at $SSH_KEY."

REMOTE_USER_HOST="ubuntu@$LINUX_IP"
REMOTE_BASE="/tmp/tf-aws-soc-e2e-${SIMULATION}-$$"
REMOTE_CLEANUP_NEEDED=false

cleanup_remote() {
    if [ "$REMOTE_CLEANUP_NEEDED" != "true" ]; then
        return 0
    fi
    echo ""
    echo "Cleaning up remote workspace..."
    run_remote "REMOTE_BASE='$REMOTE_BASE' E2E_SSH_USER='$E2E_SSH_USER' bash -lc $(printf '%q' "$RESTORE_COMMAND; rm -rf '$REMOTE_BASE'")" || true
}

trap cleanup_remote EXIT

echo "Wazuh server: ubuntu@$WAZUH_IP"
echo "Linux endpoint: $REMOTE_USER_HOST"
echo "SSH key: $SSH_KEY"
echo "Simulation: $SIMULATION"
echo ""

echo "Creating remote workspace..."
run_remote "mkdir -p '$REMOTE_BASE/attack-simulation'"
REMOTE_CLEANUP_NEEDED=true

echo "Copying simulation assets to Linux endpoint..."
scp -o StrictHostKeyChecking=no -o ConnectTimeout=10 -i "$SSH_KEY" -o ProxyJump="ubuntu@$WAZUH_IP" \
    "$PROJECT_ROOT/attack-simulation/common.sh" \
    "$PROJECT_ROOT/attack-simulation/$SIMULATION_SCRIPT" \
    "$REMOTE_USER_HOST:$REMOTE_BASE/attack-simulation/"

echo "Preparing Linux endpoint for simulation..."
run_remote "REMOTE_BASE='$REMOTE_BASE' E2E_SSH_USER='$E2E_SSH_USER' E2E_SSH_PASSWORD='$E2E_SSH_PASSWORD' bash -lc $(printf '%q' "$PREP_COMMAND")"

echo "Executing simulation on Linux endpoint..."
run_remote "cd '$REMOTE_BASE/attack-simulation' && chmod +x common.sh '$SIMULATION_SCRIPT' && ${REMOTE_ENV}bash './$SIMULATION_SCRIPT' --force"

echo ""
echo "Simulation complete. Validating detections on Wazuh..."
"$SMOKE_WRAPPER" --timeout "$TIMEOUT" --ssh-target "ubuntu@$WAZUH_IP" --ssh-key "$SSH_KEY" \
    $(printf -- '--rule-id %s ' "${SMOKE_RULE_IDS[@]}")

echo ""
echo "End-to-end detection test passed."
