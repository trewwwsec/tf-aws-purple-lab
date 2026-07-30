#!/bin/bash
# =============================================================================
# Common Utilities for Attack Simulation Scripts
# Purple Lab
# =============================================================================
#
# This library provides shared functions for all attack simulation scripts.
# Source this file at the beginning of your script:
#   source "$(dirname "$0")/common.sh"
#
# =============================================================================

# Ensure this script is sourced, not executed
if [ "${BASH_SOURCE[0]}" -ef "$0" ]; then
    echo "Error: This script should be sourced, not executed directly"
    exit 1
fi

# =============================================================================
# COLORS
# =============================================================================

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# =============================================================================
# LOGGING
# =============================================================================

# Setup logging to file
# Usage: setup_logging [log_file_path]
setup_logging() {
    local log_file="${1:-simulation.log}"
    exec 1> >(tee -a "$log_file")
    exec 2>&1
}

# Log with timestamp
# Usage: log_info "message"
log_info() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] INFO:${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARN:${NC} $1"
}

log_error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
}

# Simple log action (for backward compatibility)
# Usage: log_action "description"
log_action() {
    log_info "$1"
}

# =============================================================================
# SAFETY CHECKS
# =============================================================================

# Display safety warning and request confirmation
# Usage: safety_check "attack description" [--force]
# Options:
#   --force or -y  Skip confirmation (for automation)
safety_check() {
    local attack_type="$1"
    local force_mode=false
    
    # Check for force flag
    for arg in "$@"; do
        case "$arg" in
            --force|-y|-f)
                force_mode=true
                ;;
        esac
    done
    
    if [ "$force_mode" = true ]; then
        log_warn "Force mode enabled - skipping safety check"
        return 0
    fi
    
    echo -e "${RED}⚠️  WARNING: This script simulates ${attack_type}!${NC}"
    echo -e "${YELLOW}Only run in isolated lab environments.${NC}"
    echo ""
    
    read -p "Are you sure you want to continue? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        echo -e "${YELLOW}Simulation cancelled.${NC}"
        exit 0
    fi
}

# Check if running on Darwin (macOS)
# Usage: if is_darwin; then ... fi
is_darwin() {
    [[ "$OSTYPE" == "darwin"* ]]
}

# Check if running on Linux
# Usage: if is_linux; then ... fi
is_linux() {
    [[ "$OSTYPE" == "linux"* ]]
}

# =============================================================================
# WAZUH INTEGRATION
# =============================================================================

# Check for alerts in Wazuh server
# Usage: check_wazuh_alerts "search_pattern"
check_wazuh_alerts() {
    local pattern="$1"
    
    if [ -z "$WAZUH_SERVER" ]; then
        echo -e "${YELLOW}Set WAZUH_SERVER environment variable to check alerts${NC}"
        echo "Example: export WAZUH_SERVER='ubuntu@10.0.1.10'"
        return 1
    fi
    
    echo ""
    echo "Checking Wazuh server for alerts matching: $pattern"
    
    if ssh "$WAZUH_SERVER" "sudo tail -n 100 /var/ossec/logs/alerts/alerts.log | grep -i '$pattern'" 2>/dev/null; then
        echo -e "${GREEN}✓ Alerts found${NC}"
        return 0
    else
        echo -e "${YELLOW}No matching alerts found (may need more time)${NC}"
        return 1
    fi
}

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

# Print a formatted header
# Usage: print_header "Title"
print_header() {
    local title="$1"
    local width=68
    local padding=$(( (width - ${#title}) / 2 ))
    
    echo -e "${BLUE}╔$(printf '═%.0s' $(seq 1 $width))╗${NC}"
    printf "${BLUE}║${NC} %${padding}s%s%${padding}s ${BLUE}║${NC}\n" "" "$title" ""
    echo -e "${BLUE}╚$(printf '═%.0s' $(seq 1 $width))╝${NC}"
    echo ""
}

# Print a section header
# Usage: print_section "Emoji" "Title"
print_section() {
    local emoji="$1"
    local title="$2"
    echo -e "${BLUE}${emoji} ${title}:${NC}"
}

# Wait with progress indicator
# Usage: wait_with_message "Message" 5
wait_with_message() {
    local message="$1"
    local seconds="${2:-2}"
    
    echo "$message"
    sleep "$seconds"
}

# Cleanup function registration
# Usage: register_cleanup "cleanup_function_name"
register_cleanup() {
    local cleanup_func="$1"
    trap "$cleanup_func" EXIT INT TERM
}

# =============================================================================
# VALIDATION
# =============================================================================

# Check if required command exists
# Usage: require_command "sshpass" "Please install sshpass"
require_command() {
    local cmd="$1"
    local msg="${2:-$1 is required but not installed}"
    
    if ! command -v "$cmd" &> /dev/null; then
        log_error "$msg"
        exit 1
    fi
}

# Check if environment variable is set
# Usage: require_env "WAZUH_SERVER" "Wazuh server IP"
require_env() {
    local var="$1"
    local description="${2:-$1}"
    
    if [ -z "${!var}" ]; then
        log_warn "Environment variable $var not set ($description)"
        return 1
    fi
    return 0
}
