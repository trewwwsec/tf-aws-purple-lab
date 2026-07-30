#!/bin/bash
#
# Evidence Collection Tool
# Collects forensic evidence from a system during incident response
#
# This script always collects from the LOCAL machine it runs on. Run it
# directly on the target host (e.g. after SSHing in) rather than pointing
# it at a remote host — <hostname> is only used as a label in the output.
#
# Usage: ./collect-evidence.sh <hostname> <incident-id>
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check arguments
if [ $# -lt 2 ]; then
    echo "Usage: $0 <hostname> <incident-id>"
    echo "Example: $0 web-server-01 INC-20260128-001"
    echo ""
    echo "Run this script directly on the target host; <hostname> is a label only."
    exit 1
fi

HOSTNAME=$1
INCIDENT_ID=$2
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/evidence/$INCIDENT_ID-$TIMESTAMP"

echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                                                          ║${NC}"
echo -e "${BLUE}║        Evidence Collection Tool                         ║${NC}"
echo -e "${BLUE}║        Purple Lab                               ║${NC}"
echo -e "${BLUE}║                                                          ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${YELLOW}Incident ID:${NC} $INCIDENT_ID"
echo -e "${YELLOW}Target System:${NC} $HOSTNAME"
echo -e "${YELLOW}Evidence Directory:${NC} $EVIDENCE_DIR"
echo ""

# Create evidence directory
mkdir -p "$EVIDENCE_DIR"
cd "$EVIDENCE_DIR"

# Create chain of custody log
cat > chain-of-custody.txt << EOF
CHAIN OF CUSTODY LOG
=====================
Incident ID: $INCIDENT_ID
System: $HOSTNAME
Collection Date: $(date)
Collected By: $(whoami)
Collection Tool: Evidence Collection Script v1.0

Evidence Items:
---------------
EOF

# Function to log evidence collection
log_evidence() {
    local item=$1
    local description=$2
    echo "[$TIMESTAMP] $item - $description" >> chain-of-custody.txt
    echo -e "${GREEN}✓${NC} Collected: $description"
}

echo -e "${BLUE}[1/10]${NC} Collecting System Information..."
{
    echo "=== SYSTEM INFORMATION ==="
    echo "Hostname: $(hostname)"
    echo "Kernel: $(uname -a)"
    echo "OS: $(cat /etc/os-release 2>/dev/null || echo 'Unknown')"
    echo "Uptime: $(uptime)"
    echo "Current Time: $(date)"
    echo "Timezone: $(timedatectl 2>/dev/null || date +%Z)"
} > system-info.txt
log_evidence "EVD-001" "System information"

echo -e "${BLUE}[2/10]${NC} Collecting User Information..."
{
    echo "=== LOGGED IN USERS ==="
    who
    echo ""
    echo "=== USER LIST ==="
    w
    echo ""
    echo "=== LOGIN HISTORY ==="
    last -20
    echo ""
    echo "=== FAILED LOGIN ATTEMPTS ==="
    sudo lastb -20 2>/dev/null || echo "lastb not available"
} > user-info.txt
log_evidence "EVD-002" "User and login information"

echo -e "${BLUE}[3/10]${NC} Collecting Process Information..."
{
    echo "=== RUNNING PROCESSES ==="
    ps auxf
    echo ""
    echo "=== PROCESS TREE ==="
    pstree -p 2>/dev/null || echo "pstree not available"
    echo ""
    echo "=== TOP PROCESSES ==="
    top -b -n 1 | head -20
} > processes.txt
log_evidence "EVD-003" "Running processes"

echo -e "${BLUE}[4/10]${NC} Collecting Network Information..."
{
    echo "=== NETWORK INTERFACES ==="
    ip addr show
    echo ""
    echo "=== ROUTING TABLE ==="
    ip route show
    echo ""
    echo "=== ACTIVE CONNECTIONS ==="
    sudo netstat -tunap 2>/dev/null || ss -tunap
    echo ""
    echo "=== LISTENING PORTS ==="
    sudo netstat -tlnp 2>/dev/null || ss -tlnp
    echo ""
    echo "=== ARP TABLE ==="
    arp -a
} > network-info.txt
log_evidence "EVD-004" "Network configuration and connections"

echo -e "${BLUE}[5/10]${NC} Collecting Authentication Logs..."
if [ -f /var/log/auth.log ]; then
    sudo cp /var/log/auth.log* . 2>/dev/null || true
    log_evidence "EVD-005" "Authentication logs (auth.log)"
elif [ -f /var/log/secure ]; then
    sudo cp /var/log/secure* . 2>/dev/null || true
    log_evidence "EVD-005" "Authentication logs (secure)"
fi

echo -e "${BLUE}[6/10]${NC} Collecting System Logs..."
sudo cp /var/log/syslog* . 2>/dev/null || sudo cp /var/log/messages* . 2>/dev/null || true
log_evidence "EVD-006" "System logs"

echo -e "${BLUE}[7/10]${NC} Collecting Cron Jobs..."
{
    echo "=== ROOT CRONTAB ==="
    sudo crontab -l 2>/dev/null || echo "No root crontab"
    echo ""
    echo "=== USER CRONTABS ==="
    for user in $(cut -d: -f1 /etc/passwd); do
        echo "--- $user ---"
        sudo crontab -u $user -l 2>/dev/null || echo "No crontab"
    done
    echo ""
    echo "=== SYSTEM CRON JOBS ==="
    sudo ls -la /etc/cron.* 2>/dev/null || true
} > cron-jobs.txt
log_evidence "EVD-007" "Scheduled tasks (cron)"

echo -e "${BLUE}[8/10]${NC} Collecting File System Information..."
{
    echo "=== MOUNTED FILESYSTEMS ==="
    mount
    echo ""
    echo "=== DISK USAGE ==="
    df -h
    echo ""
    echo "=== RECENTLY MODIFIED FILES (last 24 hours) ==="
    sudo find /etc /home /var /tmp -type f -mtime -1 2>/dev/null | head -100
    echo ""
    echo "=== SUID/SGID FILES ==="
    sudo find / -perm -4000 -o -perm -2000 -type f 2>/dev/null | head -50
} > filesystem-info.txt
log_evidence "EVD-008" "File system information"

echo -e "${BLUE}[9/10]${NC} Collecting Bash Histories..."
{
    for user in $(cut -d: -f1 /etc/passwd); do
        if [ -f /home/$user/.bash_history ]; then
            echo "=== $user ==="
            sudo cat /home/$user/.bash_history 2>/dev/null || echo "Cannot read"
            echo ""
        fi
    done
    if [ -f /root/.bash_history ]; then
        echo "=== root ==="
        sudo cat /root/.bash_history 2>/dev/null || echo "Cannot read"
    fi
} > bash-histories.txt
log_evidence "EVD-009" "Bash command histories"

echo -e "${BLUE}[10/11]${NC} Collecting Open Files..."
{
    echo "=== OPEN FILES ==="
    sudo lsof 2>/dev/null | head -500
} > open-files.txt
log_evidence "EVD-010" "Open files (lsof)"

echo -e "${BLUE}[11/11]${NC} Collecting Wazuh Alerts..."
if [ -d /var/ossec/logs/alerts ]; then
    mkdir -p wazuh-alerts
    sudo cp /var/ossec/logs/alerts/alerts.log wazuh-alerts/ 2>/dev/null || true
    sudo cp /var/ossec/logs/alerts/alerts.json wazuh-alerts/ 2>/dev/null || true
    log_evidence "EVD-011" "Wazuh alerts (alerts.log, alerts.json)"
else
    echo "  Wazuh alerts directory not found on this host, skipping"
fi

# Create evidence manifest
echo -e "\n${BLUE}Creating evidence manifest...${NC}"
{
    echo "EVIDENCE MANIFEST"
    echo "================="
    echo "Incident ID: $INCIDENT_ID"
    echo "System: $HOSTNAME"
    echo "Collection Date: $(date)"
    echo "Collected By: $(whoami)"
    echo ""
    echo "Files Collected:"
    ls -lh
} > manifest.txt

# Calculate checksums
echo -e "${BLUE}Calculating checksums...${NC}"
sha256sum * > checksums.sha256
log_evidence "EVD-012" "SHA256 checksums of all evidence"

# Package evidence
echo -e "\n${BLUE}Packaging evidence...${NC}"
cd ..
ARCHIVE_NAME="evidence-$INCIDENT_ID-$HOSTNAME-$TIMESTAMP.tar.gz"
tar -czf "$ARCHIVE_NAME" "$(basename $EVIDENCE_DIR)"

# Calculate archive checksum
ARCHIVE_HASH=$(sha256sum "$ARCHIVE_NAME" | awk '{print $1}')

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                                                          ║${NC}"
echo -e "${GREEN}║        Evidence Collection Complete                     ║${NC}"
echo -e "${GREEN}║                                                          ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}Evidence Archive:${NC} $ARCHIVE_NAME"
echo -e "${YELLOW}Archive Location:${NC} $(pwd)/$ARCHIVE_NAME"
echo -e "${YELLOW}Archive Size:${NC} $(du -h "$ARCHIVE_NAME" | cut -f1)"
echo -e "${YELLOW}SHA256 Hash:${NC} $ARCHIVE_HASH"
echo ""
echo -e "${GREEN}Evidence Items Collected:${NC}"
cat "$EVIDENCE_DIR/chain-of-custody.txt" | grep "EVD-"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "1. Securely transfer evidence archive to incident response storage"
echo "2. Verify checksum after transfer: sha256sum $ARCHIVE_NAME"
echo "3. Document evidence in incident report"
echo "4. Maintain chain of custody log"
echo ""
echo -e "${BLUE}Chain of Custody Log:${NC} $EVIDENCE_DIR/chain-of-custody.txt"
echo ""
