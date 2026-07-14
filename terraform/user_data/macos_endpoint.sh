#!/bin/bash
# =============================================================================
# macOS Endpoint Bootstrap Script
# Cloud SOC Platform - Wazuh Agent Installation
# =============================================================================
#
# This script runs on macOS EC2 instance boot via user_data
# It installs and configures the Wazuh agent to connect to the SIEM
#
# Variables (passed from Terraform):
#   ${wazuh_server_ip} - IP address of Wazuh server
#   ${agent_name}      - Name for this agent
#
# =============================================================================

set -e

# Configuration
WAZUH_VERSION="${wazuh_version}"
WAZUH_SERVER="${wazuh_server_ip}"
AGENT_NAME="${agent_name}"
LOG_FILE="/var/log/wazuh-setup.log"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "=========================================="
log "Starting macOS Wazuh Agent Installation"
log "=========================================="
log "Wazuh Server: $WAZUH_SERVER"
log "Agent Name: $AGENT_NAME"

# Wait for network
log "Waiting for network connectivity..."
until ping -c 1 8.8.8.8 &>/dev/null; do
    sleep 5
done
log "Network is up"

# Download Wazuh agent
log "Downloading Wazuh agent $WAZUH_VERSION..."
cd /tmp
curl -so wazuh-agent.pkg "https://packages.wazuh.com/4.x/macos/wazuh-agent-$WAZUH_VERSION-1.pkg"

# Verify download
if [ ! -f "wazuh-agent.pkg" ]; then
    log "ERROR: Failed to download Wazuh agent"
    exit 1
fi
log "Download complete"

# Install Wazuh agent
log "Installing Wazuh agent..."
sudo installer -pkg wazuh-agent.pkg -target /

# Configure agent
log "Configuring Wazuh agent..."
sudo /Library/Ossec/bin/agent-auth -m "$WAZUH_SERVER" -A "$AGENT_NAME"

# Update ossec.conf with server IP
sudo sed -i '' "s/<address>.*<\/address>/<address>$WAZUH_SERVER<\/address>/" /Library/Ossec/etc/ossec.conf

# Enable syscheck (file integrity monitoring) for macOS paths
log "Configuring File Integrity Monitoring..."
sudo cat >> /Library/Ossec/etc/ossec.conf << 'SYSCHECK'
<syscheck>
  <directories check_all="yes" realtime="yes">~/Library/LaunchAgents</directories>
  <directories check_all="yes" realtime="yes">/Library/LaunchAgents</directories>
  <directories check_all="yes" realtime="yes">/Library/LaunchDaemons</directories>
  <directories check_all="yes">~/.ssh</directories>
  <directories check_all="yes">/etc</directories>
  <directories check_all="yes">/usr/local/bin</directories>
</syscheck>
SYSCHECK

# Enable audit logging for macOS
log "Enabling macOS audit logging..."
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist 2>/dev/null || true

# Start Wazuh agent
log "Starting Wazuh agent..."
sudo /Library/Ossec/bin/wazuh-control start

# Verify agent is running
sleep 5
if pgrep -x "wazuh-agentd" > /dev/null; then
    log "SUCCESS: Wazuh agent is running"
else
    log "WARNING: Wazuh agent may not be running. Check logs."
fi

# Clean up
rm -f /tmp/wazuh-agent.pkg

log "=========================================="
log "macOS Wazuh Agent Installation Complete"
log "=========================================="
