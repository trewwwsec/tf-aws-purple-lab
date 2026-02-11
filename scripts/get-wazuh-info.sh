#!/bin/bash
# =============================================================================
# Get Wazuh Admin Credentials
# Cloud SOC Platform
# =============================================================================
#
# PURPOSE: Retrieve the Wazuh dashboard admin credentials from the deployed
#          Wazuh server so you can easily log in after standing up the env.
#
# USAGE:
#   ./scripts/get-wazuh-info.sh
#   ./scripts/get-wazuh-info.sh --ip <WAZUH_IP> --key <SSH_KEY_PATH>
#
# OPTIONS:
#   --ip    Wazuh server public IP (auto-detected from terraform output)
#   --key   Path to SSH private key (auto-detected from terraform.tfvars)
#   --all   Show all Wazuh component passwords (not just admin)
#   --help  Show this help message
#
# EXAMPLES:
#   ./scripts/get-wazuh-info.sh
#   ./scripts/get-wazuh-info.sh --all
#   ./scripts/get-wazuh-info.sh --ip 54.123.45.67
#   ./scripts/get-wazuh-info.sh --ip 54.123.45.67 --key ~/.ssh/my-key.pem
#
# =============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# Defaults
WAZUH_IP=""
SSH_KEY=""
SHOW_ALL=false
TERRAFORM_DIR=""

# Get project root (relative to this script's location)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TERRAFORM_DIR="$PROJECT_ROOT/terraform"

# ─── Functions ───────────────────────────────────────────────────────────────

print_banner() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}🔐 Wazuh Admin Credentials${NC}                                     ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${DIM}Cloud SOC Platform${NC}                                              ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_help() {
    print_banner
    echo "USAGE:"
    echo "  ./scripts/get-wazuh-info.sh [OPTIONS]"
    echo ""
    echo "OPTIONS:"
    echo "  --ip <IP>     Wazuh server public IP (auto-detected from terraform output)"
    echo "  --key <PATH>  Path to SSH private key (auto-detected from terraform.tfvars)"
    echo "  --all         Show all Wazuh component passwords (not just admin)"
    echo "  --help        Show this help message"
    echo ""
    echo "EXAMPLES:"
    echo "  ./scripts/get-wazuh-info.sh"
    echo "  ./scripts/get-wazuh-info.sh --all"
    echo "  ./scripts/get-wazuh-info.sh --ip 54.123.45.67"
    echo ""
    exit 0
}

fail() {
    echo -e "${RED}ERROR: $1${NC}" >&2
    exit 1
}

info() {
    echo -e "${DIM}  ▸ $1${NC}"
}

# ─── Parse Arguments ────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ip)
            WAZUH_IP="$2"
            shift 2
            ;;
        --key)
            SSH_KEY="$2"
            shift 2
            ;;
        --all)
            SHOW_ALL=true
            shift
            ;;
        --help|-h)
            print_help
            ;;
        *)
            fail "Unknown option: $1 (use --help for usage)"
            ;;
    esac
done

# ─── Auto-detect Wazuh IP ───────────────────────────────────────────────────

if [ -z "$WAZUH_IP" ]; then
    info "Auto-detecting Wazuh server IP from Terraform..."

    if ! command -v terraform &> /dev/null; then
        fail "terraform not found. Install Terraform or use --ip <IP> to specify manually."
    fi

    if [ ! -d "$TERRAFORM_DIR/.terraform" ]; then
        fail "Terraform not initialized. Run 'terraform init' in $TERRAFORM_DIR or use --ip <IP>."
    fi

    WAZUH_IP=$(cd "$TERRAFORM_DIR" && terraform output -raw wazuh_server_public_ip 2>/dev/null) || true

    if [ -z "$WAZUH_IP" ]; then
        fail "Could not get Wazuh IP from Terraform output. Is the infrastructure deployed?\n       Use --ip <IP> to specify manually."
    fi

    info "Found Wazuh server at ${BOLD}$WAZUH_IP${NC}"
fi

# ─── Auto-detect SSH Key ────────────────────────────────────────────────────

if [ -z "$SSH_KEY" ]; then
    info "Auto-detecting SSH key from terraform.tfvars..."

    TFVARS_FILE="$TERRAFORM_DIR/terraform.tfvars"

    if [ -f "$TFVARS_FILE" ]; then
        # Extract ssh_private_key_path from tfvars
        SSH_KEY=$(grep -oP 'ssh_private_key_path\s*=\s*"\K[^"]+' "$TFVARS_FILE" 2>/dev/null || \
                  grep 'ssh_private_key_path' "$TFVARS_FILE" | sed 's/.*=\s*"\(.*\)"/\1/' 2>/dev/null) || true

        # Expand ~ to $HOME
        SSH_KEY="${SSH_KEY/#\~/$HOME}"
    fi

    if [ -z "$SSH_KEY" ]; then
        # Fallback: try common key names
        for key_path in ~/.ssh/cloud-soc-key.pem ~/.ssh/cloud-soc-key; do
            if [ -f "$key_path" ]; then
                SSH_KEY="$key_path"
                break
            fi
        done
    fi

    if [ -z "$SSH_KEY" ]; then
        fail "Could not find SSH key. Use --key <PATH> to specify manually."
    fi

    info "Using SSH key at ${BOLD}$SSH_KEY${NC}"
fi

# ─── Validate SSH Key ───────────────────────────────────────────────────────

SSH_KEY="${SSH_KEY/#\~/$HOME}"

if [ ! -f "$SSH_KEY" ]; then
    fail "SSH key not found at: $SSH_KEY"
fi

# ─── Retrieve Credentials ───────────────────────────────────────────────────

echo ""
info "Connecting to Wazuh server at $WAZUH_IP..."

# SSH into the server and extract the passwords
PASSWORDS_OUTPUT=$(ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=10 \
    -o BatchMode=yes \
    -i "$SSH_KEY" \
    "ubuntu@$WAZUH_IP" \
    "sudo tar -xf /home/ubuntu/wazuh-install-files.tar -C /tmp 2>/dev/null; sudo cat /tmp/wazuh-install-files/wazuh-passwords.txt 2>/dev/null || sudo cat /home/ubuntu/wazuh-install-files/wazuh-passwords.txt 2>/dev/null || echo 'CREDS_NOT_FOUND'" \
    2>/dev/null) || fail "SSH connection failed. Is the server running and reachable?"

if [[ "$PASSWORDS_OUTPUT" == *"CREDS_NOT_FOUND"* ]]; then
    fail "Credentials file not found on the Wazuh server.\n       The Wazuh installation may not have completed yet (~10 min after deploy)."
fi

# ─── Parse and Display ──────────────────────────────────────────────────────

print_banner

# Extract the admin password
ADMIN_PASSWORD=$(echo "$PASSWORDS_OUTPUT" | grep -A1 "indexer_username.*admin" | grep "indexer_password" | awk -F"'" '{print $2}' 2>/dev/null || true)

# If the first pattern didn't match, try alternative patterns
if [ -z "$ADMIN_PASSWORD" ]; then
    ADMIN_PASSWORD=$(echo "$PASSWORDS_OUTPUT" | grep -A1 "'admin'" | grep "password" | awk -F"'" '{print $2}' 2>/dev/null || true)
fi

if [ -z "$ADMIN_PASSWORD" ]; then
    # Last resort: try to extract from the raw output
    ADMIN_PASSWORD=$(echo "$PASSWORDS_OUTPUT" | grep -m1 "password.*admin\|admin.*password" | awk -F"'" '{print $2}' 2>/dev/null || true)
fi

if [ -n "$ADMIN_PASSWORD" ]; then
    echo -e "  ${BOLD}Dashboard URL${NC}     https://$WAZUH_IP"
    echo -e "  ${BOLD}Username${NC}          admin"
    echo -e "  ${BOLD}Password${NC}          ${GREEN}$ADMIN_PASSWORD${NC}"
    echo ""
    echo -e "  ${DIM}(Accept the self-signed certificate warning in your browser)${NC}"
else
    echo -e "  ${YELLOW}Could not parse admin password. Showing raw output below.${NC}"
    SHOW_ALL=true
fi

# Show all passwords if requested
if [ "$SHOW_ALL" = true ]; then
    echo ""
    echo -e "${CYAN}───────────────────────────────────────────────────────────────────${NC}"
    echo -e "  ${BOLD}All Wazuh Component Passwords${NC}"
    echo -e "${CYAN}───────────────────────────────────────────────────────────────────${NC}"
    echo ""
    echo "$PASSWORDS_OUTPUT"
fi

echo ""
echo -e "${CYAN}───────────────────────────────────────────────────────────────────${NC}"
echo -e "  ${DIM}SSH to server:${NC}  ssh -i $SSH_KEY ubuntu@$WAZUH_IP"
echo -e "${CYAN}───────────────────────────────────────────────────────────────────${NC}"
echo ""
