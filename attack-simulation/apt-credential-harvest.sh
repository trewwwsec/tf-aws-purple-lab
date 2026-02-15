#!/bin/bash
# =============================================================================
# APT Credential Harvesting Simulation
# Cloud SOC Platform - Purple Team Testing
# =============================================================================
#
# PURPOSE: Simulate credential theft techniques used by APT29, APT28,
#          Lazarus Group, and FIN7 to validate SIEM detections.
#
# WARNING: FOR AUTHORIZED TESTING ONLY - Run only in controlled environments
#
# MITRE ATT&CK Coverage:
#   T1003.008 - /etc/passwd and /etc/shadow (Linux)
#   T1555.001 - Keychain (macOS)
#   T1552.004 - Private Keys (SSH)
#   T1552.003 - Bash History
#   T1552.001 - Credentials in Files (Cloud)
#   T1558.003 - Kerberoasting
#   T1555.003 - Credentials from Web Browsers
#   T1003.007 - Proc Filesystem (Linux)
#
# PLATFORMS: Linux, macOS
#
# =============================================================================

set -euo pipefail

# Source common library
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

# Temp directory for artifacts (cleaned up on exit)
WORKDIR=$(mktemp -d /tmp/soc-sim-cred-XXXXXX)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$SCRIPT_DIR/logs/apt-credential-harvest_${TIMESTAMP}.log"
mkdir -p "$SCRIPT_DIR/logs"

# Cleanup on exit
cleanup() {
    log_info "Cleaning up simulation artifacts..."
    rm -rf "$WORKDIR"
    log_info "Cleanup complete."
}
register_cleanup cleanup

# =============================================================================
# TEST FUNCTIONS
# =============================================================================

# Test 1: Credential Store Access (APT28 - T1003.008 / T1555.001)
test_credential_store_access() {
    if is_linux; then
        print_section "🔓" "Shadow File Access (T1003.008 — APT28)"
        log_info "[1/8] Attempting to read /etc/shadow (credential dumping)"

        echo -e "  ${YELLOW}▸${NC} Attempting: cat /etc/shadow"
        cat /etc/shadow > "$WORKDIR/shadow_dump.txt" 2>&1 || true
        log_info "Direct shadow read attempted"

        echo -e "  ${YELLOW}▸${NC} Attempting: paste /etc/passwd /etc/shadow"
        paste /etc/passwd /etc/shadow > "$WORKDIR/unshadow.txt" 2>&1 || true
        log_info "Unshadow merge attempted"

        echo -e "  ${YELLOW}▸${NC} Attempting: getent shadow"
        getent shadow > "$WORKDIR/getent_shadow.txt" 2>&1 || true
        log_info "getent shadow attempted"

        echo -e "  ${GREEN}Expected Alerts:${NC} Rule 100070 (credential dump), Wazuh syscheck"

    elif is_darwin; then
        print_section "🔓" "Keychain Credential Access (T1555.001 — APT29)"
        log_info "[1/8] Accessing macOS Keychain credential stores"

        echo -e "  ${YELLOW}▸${NC} Listing available keychains"
        security list-keychains 2>/dev/null || true

        echo -e "  ${YELLOW}▸${NC} Dumping keychain metadata (no passwords)"
        security dump-keychain 2>/dev/null | head -30 || true
        log_info "Keychain dump attempted"

        echo -e "  ${YELLOW}▸${NC} Checking for keychain database files"
        ls -la ~/Library/Keychains/ 2>/dev/null || true

        echo -e "  ${YELLOW}▸${NC} Attempting to find login keychain password entries"
        security find-generic-password -s "com.apple.test.soc" 2>/dev/null || \
            echo -e "    No matching entry (expected)"
        log_info "Keychain access complete"

        echo -e "  ${GREEN}Expected Alerts:${NC} Rule 100220/100221 (Keychain access)"
    fi
    echo ""
}

# Test 2: SSH Key Theft (Lazarus Group - T1552.004)
test_ssh_key_theft() {
    print_section "🔑" "SSH Key Theft (T1552.004 — Lazarus Group)"

    log_info "[2/7] Enumerating and accessing SSH private keys"

    # Enumerate SSH directories (platform-aware home dirs)
    echo -e "  ${YELLOW}▸${NC} Enumerating SSH directories across users"
    local home_dirs
    if is_darwin; then
        home_dirs="/Users/*"
    else
        home_dirs="/home/* /root"
    fi
    for user_home in $home_dirs; do
        if [ -d "$user_home/.ssh" ] 2>/dev/null; then
            echo -e "    Found: $user_home/.ssh/"
            ls -la "$user_home/.ssh/" 2>/dev/null || true
        fi
    done

    # Look for key files system-wide
    echo -e "  ${YELLOW}▸${NC} Searching for private keys system-wide"
    find / -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" \
        -o -name "*.pem" -o -name "*.key" 2>/dev/null | head -20 || true
    log_info "SSH key enumeration complete"

    # Simulate key exfiltration (copy to staging)
    echo -e "  ${YELLOW}▸${NC} Staging discovered keys to temp directory"
    cp ~/.ssh/id_* "$WORKDIR/" 2>/dev/null || echo -e "    No keys in current user's .ssh/"
    log_info "Key staging attempted"

    echo -e "  ${GREEN}Expected Alerts:${NC} Rule 100224 (SSH key access), FIM alerts"
    echo ""
}

# Test 3: Bash History Mining (APT29 - T1552.003)
test_history_mining() {
    print_section "📜" "Bash History Mining (T1552.003 — APT29)"

    log_info "[3/7] Mining shell histories for credentials"

    # Scan current user's history
    echo -e "  ${YELLOW}▸${NC} Searching bash_history for passwords and tokens"
    grep -iE "(password|passwd|token|secret|key|api_key|aws_access)" \
        ~/.bash_history 2>/dev/null | head -5 || \
        echo -e "    No credential patterns found in current history"

    # Scan all user histories (platform-aware)
    echo -e "  ${YELLOW}▸${NC} Scanning all user shell histories"
    local hist_dirs
    if is_darwin; then
        hist_dirs="/Users/*/.bash_history /Users/*/.zsh_history"
    else
        hist_dirs="/home/*/.bash_history /root/.bash_history"
    fi
    for hist in $hist_dirs; do
        if [ -f "$hist" ] 2>/dev/null; then
            echo -e "    Scanning: $hist"
            grep -iEc "(password|secret|token|key)" "$hist" 2>/dev/null || true
        fi
    done

    # Check for .mysql_history, .psql_history, .python_history
    echo -e "  ${YELLOW}▸${NC} Checking for database/REPL histories"
    for hist_file in .mysql_history .psql_history .python_history .node_repl_history; do
        find /home/ /root -name "$hist_file" 2>/dev/null | head -3 || true
    done
    log_info "History mining complete"

    echo -e "  ${GREEN}Expected Alerts:${NC} Rule 100052 (history access), file access events"
    echo ""
}

# Test 4: Cloud Credential Theft (APT29 - T1552.001)
test_cloud_credential_theft() {
    print_section "☁️" "Cloud Credential Theft (T1552.001 — APT29)"

    log_info "[4/7] Enumerating cloud API credentials"

    # AWS credentials
    echo -e "  ${YELLOW}▸${NC} Checking AWS credential locations"
    for aws_path in \
        ~/.aws/credentials \
        ~/.aws/config \
        /root/.aws/credentials \
        /etc/boto.cfg \
        ~/.boto; do
        if [ -f "$aws_path" ] 2>/dev/null; then
            echo -e "    ${RED}Found:${NC} $aws_path"
            wc -l "$aws_path" 2>/dev/null || true
        fi
    done

    # GCP credentials
    echo -e "  ${YELLOW}▸${NC} Checking GCP credential locations"
    for gcp_path in \
        ~/.config/gcloud/credentials.db \
        ~/.config/gcloud/application_default_credentials.json \
        /etc/google/auth/application_default_credentials.json; do
        if [ -f "$gcp_path" ] 2>/dev/null; then
            echo -e "    ${RED}Found:${NC} $gcp_path"
        fi
    done

    # Azure credentials
    echo -e "  ${YELLOW}▸${NC} Checking Azure credential locations"
    for az_path in \
        ~/.azure/accessTokens.json \
        ~/.azure/azureProfile.json; do
        if [ -f "$az_path" ] 2>/dev/null; then
            echo -e "    ${RED}Found:${NC} $az_path"
        fi
    done

    # Environment variable check
    echo -e "  ${YELLOW}▸${NC} Scanning environment for API keys"
    env | grep -iE "(AWS_|AZURE_|GCP_|GOOGLE_|API_KEY|SECRET)" 2>/dev/null | \
        sed 's/=.*/=<REDACTED>/' || echo -e "    No cloud vars in environment"
    log_info "Cloud credential enumeration complete"

    echo -e "  ${GREEN}Expected Alerts:${NC} File access events, suspicious file reads"
    echo ""
}

# Test 5: Kerberos Ticket Access (APT28 - T1558.003)
test_kerberos_access() {
    print_section "🎫" "Kerberos Ticket Access (T1558.003 — APT28)"

    log_info "[5/7] Attempting Kerberos credential access"

    # List cached tickets
    echo -e "  ${YELLOW}▸${NC} Listing Kerberos ticket cache"
    klist 2>/dev/null || echo -e "    klist not available or no tickets cached"

    # Search for keytab files
    echo -e "  ${YELLOW}▸${NC} Searching for keytab files"
    find / -name "*.keytab" -o -name "krb5.conf" 2>/dev/null | head -10 || true

    # Check krb5 config
    echo -e "  ${YELLOW}▸${NC} Reading Kerberos configuration"
    cat /etc/krb5.conf 2>/dev/null | head -20 || echo -e "    No krb5.conf found"

    # Check ticket cache directory
    echo -e "  ${YELLOW}▸${NC} Checking /tmp for ticket caches"
    ls -la /tmp/krb5cc_* 2>/dev/null || echo -e "    No ticket caches in /tmp"
    log_info "Kerberos access attempted"

    echo -e "  ${GREEN}Expected Alerts:${NC} File access on keytab/krb5 files"
    echo ""
}

# Test 6: Browser Credential Theft (FIN7 - T1555.003)
test_browser_credentials() {
    print_section "🌐" "Browser Credential Theft (T1555.003 — FIN7)"

    log_info "[6/7] Accessing browser credential stores"

    # Chrome (Linux paths)
    echo -e "  ${YELLOW}▸${NC} Checking Chrome credential stores"
    for profile_dir in \
        ~/.config/google-chrome/Default \
        ~/.config/chromium/Default \
        "$HOME/Library/Application Support/Google/Chrome/Default"; do
        if [ -d "$profile_dir" ] 2>/dev/null; then
            echo -e "    ${RED}Found:${NC} $profile_dir"
            ls -la "$profile_dir/Login Data" 2>/dev/null || true
            ls -la "$profile_dir/Cookies" 2>/dev/null || true
        fi
    done

    # Firefox
    echo -e "  ${YELLOW}▸${NC} Checking Firefox credential stores"
    for ff_dir in ~/.mozilla/firefox/*.default* "$HOME/Library/Application Support/Firefox/Profiles"/*; do
        if [ -d "$ff_dir" ] 2>/dev/null; then
            echo -e "    ${RED}Found:${NC} $ff_dir"
            ls -la "$ff_dir/logins.json" 2>/dev/null || true
            ls -la "$ff_dir/key4.db" 2>/dev/null || true
        fi
    done
    log_info "Browser credential access attempted"

    echo -e "  ${GREEN}Expected Alerts:${NC} Rule 100222/100223 (browser credential access)"
    echo ""
}

# Test 7: Process Memory Credential Scan (APT29 - T1003.007)
test_proc_memory() {
    print_section "🧠" "Process Memory Credential Scan (T1003.007 — APT29)"

    log_info "[7/7] Scanning process memory for credentials"

    # Enumerate interesting processes
    echo -e "  ${YELLOW}▸${NC} Listing processes with potential credentials"
    ps aux 2>/dev/null | grep -iE "(ssh-agent|gpg-agent|gnome-keyring|vault|consul)" | \
        grep -v grep || echo -e "    No credential-holding processes found"

    # Attempt /proc access (Linux only)
    if is_linux; then
        echo -e "  ${YELLOW}▸${NC} Scanning /proc for memory maps"
        for pid in $(pgrep -f "ssh-agent|gpg-agent" 2>/dev/null | head -3); do
            echo -e "    Checking /proc/$pid/maps"
            cat "/proc/$pid/maps" > "$WORKDIR/proc_${pid}_maps.txt" 2>/dev/null || true
            echo -e "    Checking /proc/$pid/environ"
            cat "/proc/$pid/environ" 2>/dev/null | tr '\0' '\n' | \
                grep -iE "(key|token|pass|secret)" | \
                sed 's/=.*/=<REDACTED>/' || true
        done
    fi

    # Check for credential files in temp locations
    echo -e "  ${YELLOW}▸${NC} Checking tmpfs for credential artifacts"
    local tmp_dirs="/tmp"
    if is_linux; then
        tmp_dirs="/tmp /dev/shm"
    fi
    find $tmp_dirs -name "*.key" -o -name "*.pem" -o -name "*token*" \
        -o -name "*credential*" 2>/dev/null | head -10 || true
    log_info "Process memory scan complete"

    echo -e "  ${GREEN}Expected Alerts:${NC} Proc access events, suspicious file searches"
    echo ""
}

# =============================================================================
# REPORT
# =============================================================================

generate_report() {
    local report_file="$SCRIPT_DIR/logs/apt-credential-harvest_${TIMESTAMP}_report.md"
    cat > "$report_file" << EOF
# APT Credential Harvest Simulation Report

**Date**: $(date '+%Y-%m-%d %H:%M:%S')
**Host**: $(hostname)
**User**: $(whoami)
**OS**: $(uname -srm)

## APT Groups Simulated
- **APT28** (Fancy Bear) — Shadow file access, Kerberos
- **APT29** (Cozy Bear) — Cloud creds, bash history, proc memory
- **Lazarus Group** — SSH key theft
- **FIN7** — Browser credential theft

## Tests Executed

| # | Technique | MITRE | Status |
|---|-----------|-------|--------|
| 1 | /etc/shadow access | T1003.008 | ✅ |
| 2 | SSH key enumeration & staging | T1552.004 | ✅ |
| 3 | Bash history mining | T1552.003 | ✅ |
| 4 | Cloud credential enumeration | T1552.001 | ✅ |
| 5 | Kerberos ticket access | T1558.003 | ✅ |
| 6 | Browser credential theft | T1555.003 | ✅ |
| 7 | Process memory scan | T1003.007 | ✅ |

## Verification
Check Wazuh dashboard for Rules: 100070, 100224, 100052, 100222, 100223, FIM events
EOF
    echo -e "${GREEN}✓${NC} Report: $report_file"
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    print_header "APT Credential Harvesting Simulation"

    safety_check "APT-style credential harvesting techniques" "$@"

    echo ""
    log_info "Starting APT credential harvesting simulation..."
    log_info "Artifacts staged in: $WORKDIR"
    log_info "Log file: $LOG_FILE"
    echo ""

    test_credential_store_access
    test_ssh_key_theft
    test_history_mining
    test_cloud_credential_theft
    test_kerberos_access
    test_browser_credentials
    test_proc_memory

    generate_report

    echo ""
    print_header "SIMULATION COMPLETE"
    log_info "All 7 credential harvesting tests completed."
    log_info "Artifacts cleaned up on exit."
    echo ""
    echo "Next steps:"
    echo "  1. Check Wazuh dashboard for generated alerts"
    echo "  2. Review the report in logs/"
    echo "  3. Validate detection coverage against MITRE ATT&CK"
    echo ""
}

main "$@"
