#!/bin/bash
# =============================================================================
# APT Lateral Movement & Discovery Simulation
# Cloud SOC Platform - Purple Team Testing
# =============================================================================
#
# PURPOSE: Simulate lateral movement and discovery techniques used by APT29,
#          APT28, and Lazarus Group to validate SIEM detections.
#
# WARNING: FOR AUTHORIZED TESTING ONLY - Run only in controlled environments
#
# MITRE ATT&CK Coverage:
#   T1046   - Network Service Discovery
#   T1552.005 - Cloud Instance Metadata API
#   T1007   - System Service Discovery
#   T1018   - Remote System Discovery
#   T1021.004 - SSH Remote Services
#   T1070.002 - Clear Linux or Mac System Logs
#   T1070.006 - Timestomp
#
# =============================================================================

set -euo pipefail

# Source common library
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

# Config
WORKDIR=$(mktemp -d /tmp/soc-sim-lateral-XXXXXX)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$SCRIPT_DIR/logs/apt-lateral-movement_${TIMESTAMP}.log"
mkdir -p "$SCRIPT_DIR/logs"

cleanup() {
    log_info "Cleaning up simulation artifacts..."
    rm -rf "$WORKDIR"
    log_info "Cleanup complete."
}
register_cleanup cleanup

# =============================================================================
# TEST FUNCTIONS
# =============================================================================

# Test 1: Internal Network Recon (APT29 - T1046)
test_network_recon() {
    print_section "🔍" "Internal Network Recon (T1046 — APT29)"

    log_info "[1/7] Network discovery using native tools (LOLBins)"

    # ARP table (discover LAN hosts without nmap)
    echo -e "  ${YELLOW}▸${NC} ARP table enumeration"
    arp -a 2>/dev/null | head -20 || ip neigh show 2>/dev/null | head -20 || true
    log_info "ARP enumeration complete"

    # Native port scanning with /dev/tcp (bash built-in, no tools needed)
    echo -e "  ${YELLOW}▸${NC} Bash /dev/tcp port scan on localhost (LOLBin technique)"
    for port in 22 80 443 8080 3306 5432 6379 8443; do
        (echo >/dev/tcp/127.0.0.1/$port) 2>/dev/null && \
            echo -e "    ${RED}Open:${NC} 127.0.0.1:$port" || true
    done
    log_info "LOLBin port scan complete"

    # DNS enumeration
    echo -e "  ${YELLOW}▸${NC} Internal DNS enumeration"
    cat /etc/resolv.conf 2>/dev/null || true
    host -t any "$(hostname -d 2>/dev/null || echo 'localdomain')" 2>/dev/null || true
    log_info "DNS enumeration complete"

    # Route table
    echo -e "  ${YELLOW}▸${NC} Route table discovery"
    ip route show 2>/dev/null || netstat -rn 2>/dev/null || route -n 2>/dev/null || true

    echo -e "  ${GREEN}Expected Alerts:${NC} Network scanning detection, LOLBin usage"
    echo ""
}

# Test 2: Cloud Metadata Harvesting (APT29 - T1552.005)
test_cloud_metadata() {
    print_section "☁️" "Cloud Metadata Harvesting (T1552.005 — APT29)"

    log_info "[2/7] Attempting cloud instance metadata API access"

    # AWS IMDSv1 (the classic SSRF target)
    echo -e "  ${YELLOW}▸${NC} AWS IMDS v1 — http://169.254.169.254/"
    curl -s --connect-timeout 2 --max-time 3 \
        http://169.254.169.254/latest/meta-data/ 2>/dev/null || \
        echo -e "    Not running on AWS (or IMDSv2 enforced — good)"

    # AWS: attempt IAM role credential theft
    echo -e "  ${YELLOW}▸${NC} AWS IMDS — IAM role credentials"
    curl -s --connect-timeout 2 --max-time 3 \
        http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null || \
        echo -e "    IAM role metadata not accessible"

    # GCP metadata
    echo -e "  ${YELLOW}▸${NC} GCP Metadata — http://metadata.google.internal/"
    curl -s --connect-timeout 2 --max-time 3 \
        -H "Metadata-Flavor: Google" \
        "http://metadata.google.internal/computeMetadata/v1/" 2>/dev/null || \
        echo -e "    Not running on GCP"

    # Azure IMDS
    echo -e "  ${YELLOW}▸${NC} Azure IMDS — http://169.254.169.254/metadata/"
    curl -s --connect-timeout 2 --max-time 3 \
        -H "Metadata: true" \
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null || \
        echo -e "    Not running on Azure"

    log_info "Cloud metadata harvesting complete"

    echo -e "  ${GREEN}Expected Alerts:${NC} IMDS access attempts, cloud metadata queries"
    echo ""
}

# Test 3: Service Enumeration (Lazarus Group - T1007)
test_service_enumeration() {
    print_section "⚙️" "Service & Scheduled Task Enumeration (T1007 — Lazarus)"

    log_info "[3/7] Enumerating system services and scheduled tasks"

    # Systemd services
    echo -e "  ${YELLOW}▸${NC} Listing active systemd services"
    systemctl list-units --type=service --state=running 2>/dev/null | head -15 || \
        service --status-all 2>/dev/null | head -15 || true

    # Interesting service discovery
    echo -e "  ${YELLOW}▸${NC} Checking for high-value services"
    for svc in docker kubelet postgresql mysql redis mongod elasticsearch vault consul; do
        if systemctl is-active "$svc" &>/dev/null; then
            echo -e "    ${RED}Running:${NC} $svc"
        fi
    done

    # Cron jobs
    echo -e "  ${YELLOW}▸${NC} Enumerating cron jobs"
    crontab -l 2>/dev/null || echo -e "    No crontab for $(whoami)"
    ls -la /etc/cron.d/ 2>/dev/null | head -10 || true
    cat /etc/crontab 2>/dev/null | grep -v "^#" | head -10 || true

    # Listening services
    echo -e "  ${YELLOW}▸${NC} Enumerating listening ports"
    ss -tlnp 2>/dev/null | head -15 || netstat -tlnp 2>/dev/null | head -15 || true
    log_info "Service enumeration complete"

    echo -e "  ${GREEN}Expected Alerts:${NC} Discovery technique alerts"
    echo ""
}

# Test 4: Living-off-the-Land Discovery (APT28 - T1018)
test_lotl_discovery() {
    print_section "🏠" "Living-off-the-Land Discovery (T1018 — APT28)"

    log_info "[4/7] Running discovery commands using only native binaries"

    # Hosts file
    echo -e "  ${YELLOW}▸${NC} Reading /etc/hosts for known hosts"
    cat /etc/hosts 2>/dev/null | grep -v "^#" | grep -v "^$" || true

    # Recent logins
    echo -e "  ${YELLOW}▸${NC} Enumerating recent logins (last/who)"
    last -10 2>/dev/null || true
    who 2>/dev/null || true

    # Users with shells
    echo -e "  ${YELLOW}▸${NC} Enumerating interactive user accounts"
    grep -E "/bin/(ba)?sh$" /etc/passwd 2>/dev/null || true

    # Sudo configuration discovery
    echo -e "  ${YELLOW}▸${NC} Checking sudo configuration"
    sudo -l 2>/dev/null | head -15 || echo -e "    Cannot list sudo privileges"

    # Open files and network connections
    echo -e "  ${YELLOW}▸${NC} Open network connections"
    lsof -i -P -n 2>/dev/null | head -20 || ss -tunp 2>/dev/null | head -20 || true

    # Mounted filesystems
    echo -e "  ${YELLOW}▸${NC} Mounted filesystems (looking for shares)"
    mount 2>/dev/null | grep -iE "(nfs|cifs|smb|fuse)" || echo -e "    No network mounts"
    log_info "LOTL discovery complete"

    echo -e "  ${GREEN}Expected Alerts:${NC} Recon command execution, user enumeration"
    echo ""
}

# Test 5: SSH Pivoting Simulation (Lazarus Group - T1021.004)
test_ssh_pivoting() {
    print_section "🔀" "SSH Pivoting Simulation (T1021.004 — Lazarus)"

    log_info "[5/7] Simulating SSH pivot techniques"

    # Check for SSH agent forwarding (critical for lateral movement)
    echo -e "  ${YELLOW}▸${NC} Checking SSH agent status"
    ssh-add -l 2>/dev/null || echo -e "    No SSH agent keys loaded"

    # Check SSH config for interesting targets
    echo -e "  ${YELLOW}▸${NC} Parsing SSH config for pivot targets"
    if [ -f ~/.ssh/config ]; then
        grep -iE "^Host " ~/.ssh/config 2>/dev/null | head -10 || true
    else
        echo -e "    No SSH config found"
    fi

    # Check known_hosts for historical connections (lateral movement intel)
    echo -e "  ${YELLOW}▸${NC} Known hosts analysis (historical connections)"
    if [ -f ~/.ssh/known_hosts ]; then
        wc -l ~/.ssh/known_hosts 2>/dev/null
        # Extract hostnames/IPs from known_hosts
        awk '{print $1}' ~/.ssh/known_hosts 2>/dev/null | \
            tr ',' '\n' | sort -u | head -10 || true
    else
        echo -e "    No known_hosts file"
    fi

    # Simulate SSH tunnel command construction (NOT executed)
    echo -e "  ${YELLOW}▸${NC} SSH tunnel commands (logged, not executed):"
    echo -e "    SOCKS proxy:   ssh -D 1080 -N -f pivot@<target>"
    echo -e "    Local forward:  ssh -L 8080:internal:80 pivot@<target>"
    echo -e "    Remote forward: ssh -R 4444:127.0.0.1:4444 pivot@<target>"
    log_info "SSH pivoting analysis complete"

    echo -e "  ${GREEN}Expected Alerts:${NC} SSH agent access, known_hosts enumeration"
    echo ""
}

# Test 6: Log Tampering (APT28 - T1070.002)
test_log_tampering() {
    print_section "🗑️" "Log Tampering Simulation (T1070.002 — APT28)"

    log_info "[6/7] Simulating log manipulation techniques"

    # Attempt to read binary login records
    echo -e "  ${YELLOW}▸${NC} Accessing wtmp/utmp binary logs"
    ls -la /var/log/wtmp 2>/dev/null || true
    last -5 2>/dev/null || true

    # Attempt to access auth logs
    echo -e "  ${YELLOW}▸${NC} Accessing authentication logs"
    tail -5 /var/log/auth.log 2>/dev/null || \
        tail -5 /var/log/secure 2>/dev/null || \
        echo -e "    Cannot read auth logs"

    # Simulate history evasion techniques
    echo -e "  ${YELLOW}▸${NC} History evasion techniques (demonstration only):"
    echo -e "    unset HISTFILE          # Prevent history recording"
    echo -e "    export HISTSIZE=0       # Zero-size history"
    echo -e "    ln -sf /dev/null ~/.bash_history   # Redirect to null"

    # Create test marker file, then attempt to remove it
    echo -e "  ${YELLOW}▸${NC} Simulating log entry cleanup"
    echo "SOC-TEST: This entry simulates an attacker log artifact" > "$WORKDIR/fake_log_entry.txt"
    rm -f "$WORKDIR/fake_log_entry.txt"
    echo -e "    Created and removed test log artifact"
    log_info "Log tampering simulation complete"

    echo -e "  ${GREEN}Expected Alerts:${NC} Rule 100052 (history deletion), log access events"
    echo ""
}

# Test 7: Timestomping (APT29 - T1070.006)
test_timestomping() {
    print_section "⏰" "Timestomping Simulation (T1070.006 — APT29)"

    log_info "[7/7] Simulating file timestamp manipulation"

    # Create a test file
    TEST_FILE="$WORKDIR/timestomp_test.txt"
    echo "Timestomp test artifact" > "$TEST_FILE"
    echo -e "  ${YELLOW}▸${NC} Created test file: $TEST_FILE"
    echo -e "    Original timestamps:"
    stat "$TEST_FILE" 2>/dev/null | grep -iE "(access|modify|change|birth)" || \
        ls -la "$TEST_FILE"

    # Timestomp to APT29's preferred technique — blend in with OS install dates
    echo -e "  ${YELLOW}▸${NC} Timestomping to system install date range"
    touch -t 202001150830.00 "$TEST_FILE"
    echo -e "    Modified timestamps:"
    stat "$TEST_FILE" 2>/dev/null | grep -iE "(access|modify|change|birth)" || \
        ls -la "$TEST_FILE"

    # Reference-based timestomping (match a system binary)
    echo -e "  ${YELLOW}▸${NC} Reference-based timestomping (matching /bin/ls)"
    touch -r /bin/ls "$TEST_FILE"
    echo -e "    Timestamps now match /bin/ls"
    log_info "Timestomping simulation complete"

    echo -e "  ${GREEN}Expected Alerts:${NC} FIM timestamp manipulation events"
    echo ""
}

# =============================================================================
# REPORT
# =============================================================================

generate_report() {
    local report_file="$SCRIPT_DIR/logs/apt-lateral-movement_${TIMESTAMP}_report.md"
    cat > "$report_file" << EOF
# APT Lateral Movement & Discovery Simulation Report

**Date**: $(date '+%Y-%m-%d %H:%M:%S')
**Host**: $(hostname)
**User**: $(whoami)
**OS**: $(uname -srm)

## APT Groups Simulated
- **APT29** (Cozy Bear) — Network recon, cloud metadata, timestomping
- **APT28** (Fancy Bear) — LOTL discovery, log tampering
- **Lazarus Group** — Service enumeration, SSH pivoting

## Tests Executed

| # | Technique | MITRE | Status |
|---|-----------|-------|--------|
| 1 | Internal network recon (LOLBins) | T1046 | ✅ |
| 2 | Cloud metadata harvesting | T1552.005 | ✅ |
| 3 | Service & scheduled task enum | T1007 | ✅ |
| 4 | Living-off-the-land discovery | T1018 | ✅ |
| 5 | SSH pivoting analysis | T1021.004 | ✅ |
| 6 | Log tampering simulation | T1070.002 | ✅ |
| 7 | Timestomping | T1070.006 | ✅ |

## Verification
Check Wazuh dashboard for: network discovery, IMDS access, service enum, FIM events
EOF
    echo -e "${GREEN}✓${NC} Report: $report_file"
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    print_header "APT Lateral Movement & Discovery Simulation"

    safety_check "APT-style lateral movement and discovery techniques" "$@"

    echo ""
    log_info "Starting APT lateral movement simulation..."
    log_info "Artifacts staged in: $WORKDIR"
    log_info "Log file: $LOG_FILE"
    echo ""

    test_network_recon
    test_cloud_metadata
    test_service_enumeration
    test_lotl_discovery
    test_ssh_pivoting
    test_log_tampering
    test_timestomping

    generate_report

    echo ""
    print_header "SIMULATION COMPLETE"
    log_info "All 7 lateral movement tests completed."
    log_info "Artifacts cleaned up on exit."
    echo ""
    echo "Next steps:"
    echo "  1. Check Wazuh dashboard for generated alerts"
    echo "  2. Review the report in logs/"
    echo "  3. Validate detection coverage against MITRE ATT&CK"
    echo ""
}

main "$@"
