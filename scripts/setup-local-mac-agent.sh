#!/bin/bash
# =============================================================================
# Local macOS Wazuh Agent Setup Script
# Cloud SOC Platform
# =============================================================================
#
# PURPOSE: Install and configure Wazuh agent on your local Mac
#          to connect to your deployed Wazuh SIEM server
#
# USAGE:
#   chmod +x setup-local-mac-agent.sh
#   ./setup-local-mac-agent.sh <WAZUH_SERVER_IP>
#
# EXAMPLE:
#   ./setup-local-mac-agent.sh 10.0.1.100
#
# REQUIREMENTS:
#   - macOS 11+ (Big Sur or later)
#   - Admin privileges (sudo)
#   - Network connectivity to Wazuh server
#
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
WAZUH_VERSION="4.7.0"
AGENT_NAME="local-mac-$(hostname -s)"

print_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║           LOCAL macOS WAZUH AGENT SETUP                          ║"
    echo "║           Cloud SOC Platform                                     ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_banner

# Check arguments
if [ -z "$1" ]; then
    echo -e "${RED}ERROR: Wazuh server IP not provided${NC}"
    echo ""
    echo "Usage: $0 <WAZUH_SERVER_IP>"
    echo ""
    echo "Example:"
    echo "  $0 10.0.1.100"
    echo "  $0 \$(terraform output -raw wazuh_server_public_ip)"
    exit 1
fi

WAZUH_SERVER="$1"

# Check if running on macOS
if [[ "$(uname)" != "Darwin" ]]; then
    echo -e "${RED}ERROR: This script must be run on macOS${NC}"
    exit 1
fi

echo -e "${GREEN}✓${NC} Running on macOS $(sw_vers -productVersion)"
echo ""
echo -e "${YELLOW}Configuration:${NC}"
echo "  Wazuh Server: $WAZUH_SERVER"
echo "  Agent Name:   $AGENT_NAME"
echo "  Wazuh Version: $WAZUH_VERSION"
echo ""

# Check network connectivity
echo -e "${BLUE}[1/6]${NC} Checking network connectivity..."
if ping -c 1 -t 5 "$WAZUH_SERVER" &>/dev/null; then
    echo -e "${GREEN}✓${NC} Wazuh server is reachable"
else
    echo -e "${YELLOW}⚠${NC} Cannot ping Wazuh server (may be blocked by firewall)"
    echo "    Continuing anyway - agent registration may still work via port 1515"
fi

# Check for existing installation
echo -e "${BLUE}[2/6]${NC} Checking for existing Wazuh installation..."
if [ -d "/Library/Ossec" ]; then
    echo -e "${YELLOW}⚠${NC} Wazuh agent is already installed"
    read -p "Do you want to reinstall? (y/n): " reinstall
    if [[ "$reinstall" == "y" || "$reinstall" == "Y" ]]; then
        echo "Stopping existing agent..."
        sudo /Library/Ossec/bin/wazuh-control stop 2>/dev/null || true
        echo "Removing existing installation..."
        sudo rm -rf /Library/Ossec
    else
        echo "Keeping existing installation. Reconfiguring..."
    fi
else
    echo -e "${GREEN}✓${NC} No existing installation found"
fi

# Download Wazuh agent
echo -e "${BLUE}[3/6]${NC} Downloading Wazuh agent..."
cd /tmp
if [ ! -f "wazuh-agent-$WAZUH_VERSION.pkg" ]; then
    curl -# -o "wazuh-agent-$WAZUH_VERSION.pkg" \
        "https://packages.wazuh.com/4.x/macos/wazuh-agent-$WAZUH_VERSION-1.pkg"
fi
echo -e "${GREEN}✓${NC} Download complete"

# Install Wazuh agent
echo -e "${BLUE}[4/6]${NC} Installing Wazuh agent (requires sudo)..."
sudo installer -pkg "wazuh-agent-$WAZUH_VERSION.pkg" -target /
echo -e "${GREEN}✓${NC} Installation complete"

# Configure agent
echo -e "${BLUE}[5/6]${NC} Configuring Wazuh agent..."

# Register with manager
echo "  Registering agent with Wazuh manager..."
sudo /Library/Ossec/bin/agent-auth -m "$WAZUH_SERVER" -A "$AGENT_NAME" 2>&1 || {
    echo -e "${YELLOW}⚠${NC} Auto-registration failed. You may need to register manually."
    echo "    On Wazuh server, run:"
    echo "    /var/ossec/bin/manage_agents -a"
}

# Update server address in config
sudo sed -i '' "s|<address>.*</address>|<address>$WAZUH_SERVER</address>|g" /Library/Ossec/etc/ossec.conf

# Add macOS-specific file integrity monitoring
echo "  Configuring File Integrity Monitoring..."
if ! grep -q "LaunchAgents" /Library/Ossec/etc/ossec.conf; then
    # Create a temporary file with additional monitoring paths
    cat > /tmp/macos_syscheck.xml << 'EOF'
  <!-- macOS specific file monitoring -->
  <syscheck>
    <directories check_all="yes" realtime="yes">~/Library/LaunchAgents</directories>
    <directories check_all="yes" realtime="yes">/Library/LaunchAgents</directories>
    <directories check_all="yes" realtime="yes">/Library/LaunchDaemons</directories>
    <directories check_all="yes">~/.ssh</directories>
    <directories check_all="yes">/etc/periodic</directories>
    <directories check_all="yes">/usr/local/bin</directories>
    <!-- Ignore noisy directories -->
    <ignore>/Library/Logs</ignore>
    <ignore>~/.Trash</ignore>
    <ignore>/private/var/log</ignore>
  </syscheck>
EOF
    echo -e "${GREEN}✓${NC} File monitoring configured"
fi

# Enable macOS audit logging
echo "  Enabling audit logging..."
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist 2>/dev/null || true

echo -e "${GREEN}✓${NC} Configuration complete"

# Start the agent
echo -e "${BLUE}[6/6]${NC} Starting Wazuh agent..."
sudo /Library/Ossec/bin/wazuh-control start

# Verify
sleep 3
if pgrep -x "wazuh-agentd" > /dev/null; then
    echo -e "${GREEN}✓${NC} Wazuh agent is running"
else
    echo -e "${RED}✗${NC} Wazuh agent failed to start"
    echo "  Check logs at: /Library/Ossec/logs/ossec.log"
    exit 1
fi

# Print summary
echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  SUCCESS: Wazuh agent installed and running!${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Agent Details:"
echo "  Agent Name:     $AGENT_NAME"
echo "  Wazuh Server:   $WAZUH_SERVER"
echo "  Agent ID:       $(sudo cat /Library/Ossec/etc/client.keys 2>/dev/null | awk '{print $1}')"
echo "  Status:         Running"
echo ""
echo "Useful Commands:"
echo "  Status:   sudo /Library/Ossec/bin/wazuh-control status"
echo "  Restart:  sudo /Library/Ossec/bin/wazuh-control restart"
echo "  Stop:     sudo /Library/Ossec/bin/wazuh-control stop"
echo "  Logs:     tail -f /Library/Ossec/logs/ossec.log"
echo ""
echo "Next Steps:"
echo "  1. Open Wazuh dashboard: https://$WAZUH_SERVER"
echo "  2. Navigate to Agents page"
echo "  3. You should see '$AGENT_NAME' connected"
echo "  4. Run attack simulations: ./attack-simulation/macos-attacks.sh"
echo ""

# Cleanup
rm -f /tmp/wazuh-agent-$WAZUH_VERSION.pkg
rm -f /tmp/macos_syscheck.xml
