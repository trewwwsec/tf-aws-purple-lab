#!/bin/bash
# =============================================================================
# macOS Attack Simulation Suite
# Cloud SOC Platform - Purple Team Testing
# =============================================================================
#
# PURPOSE: Simulate common macOS attack techniques to validate SIEM detections
# WARNING: FOR AUTHORIZED TESTING ONLY - Run only in controlled environments
#
# MITRE ATT&CK Coverage:
#   - T1543.001 - Launch Agent (Persistence)
#   - T1059.002 - AppleScript (Execution)
#   - T1555.001 - Keychain (Credential Access)
#   - T1553.001 - Gatekeeper Bypass (Defense Evasion)
#   - T1082 - System Information Discovery
#   - T1113 - Screen Capture (Collection)
#
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${SCRIPT_DIR}/logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${LOG_DIR}/macos_attack_simulation_${TIMESTAMP}.log"

# Create log directory
mkdir -p "$LOG_DIR"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

print_banner() {
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║           macOS ATTACK SIMULATION SUITE                          ║"
    echo "║           Cloud SOC Platform - Purple Team                       ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_section() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

print_test() {
    echo -e "  ${GREEN}▶${NC} $1"
    log "EXECUTING: $1"
}

print_expected() {
    echo -e "    ${YELLOW}Expected Alert:${NC} $1"
}

# Safety checks
safety_check() {
    print_section "SAFETY CHECKS"
    
    # Check if running on macOS
    if [[ "$(uname)" != "Darwin" ]]; then
        echo -e "${RED}ERROR: This script must be run on macOS${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓${NC} Running on macOS $(sw_vers -productVersion)"
    
    # Check if authorized
    echo ""
    echo -e "${YELLOW}⚠️  WARNING: This script simulates attack techniques${NC}"
    echo -e "${YELLOW}    Only run on systems you own or have authorization to test${NC}"
    echo ""
    read -p "Do you have authorization to run these tests? (yes/no): " auth
    
    if [[ "$auth" != "yes" ]]; then
        echo -e "${RED}Aborting. Authorization required.${NC}"
        exit 1
    fi
    
    log "Authorization confirmed. Starting tests."
}

# =============================================================================
# PERSISTENCE SIMULATIONS
# =============================================================================

test_persistence() {
    print_section "PERSISTENCE TECHNIQUES (T1543)"
    
    # Test 1: Create Launch Agent (T1543.001)
    print_test "Creating test Launch Agent (T1543.001)"
    
    LAUNCH_AGENT_DIR="$HOME/Library/LaunchAgents"
    LAUNCH_AGENT_FILE="$LAUNCH_AGENT_DIR/com.test.socplatform.plist"
    
    mkdir -p "$LAUNCH_AGENT_DIR"
    
    cat > "$LAUNCH_AGENT_FILE" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.test.socplatform</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/echo</string>
        <string>SOC Platform Test</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>Disabled</key>
    <true/>
</dict>
</plist>
EOF
    
    print_expected "Rule 200200 - Launch Agent created"
    sleep 2
    
    # Cleanup
    rm -f "$LAUNCH_AGENT_FILE"
    echo -e "    ${GREEN}✓${NC} Cleaned up test Launch Agent"
    
    # Test 2: Login Items simulation (T1547.015)
    print_test "Simulating Login Items access (T1547.015)"
    ls -la "$HOME/Library/Application Support/com.apple.backgroundtaskmanagementagent/" 2>/dev/null || true
    print_expected "Rule 200202 - Login Items accessed"
    sleep 1
    
    log "Persistence tests completed"
}

# =============================================================================
# EXECUTION SIMULATIONS
# =============================================================================

test_execution() {
    print_section "EXECUTION TECHNIQUES (T1059)"
    
    # Test 1: osascript execution (T1059.002)
    print_test "Executing AppleScript via osascript (T1059.002)"
    osascript -e 'display notification "SOC Platform Test" with title "Security Test"' 2>/dev/null || true
    print_expected "Rule 200210 - osascript executed"
    sleep 1
    
    # Test 2: osascript with shell command (T1059.002 + T1059.004)
    print_test "osascript executing shell command (T1059.002)"
    osascript -e 'do shell script "echo SOC Platform Test"' 2>/dev/null || true
    print_expected "Rule 200212 - osascript shell execution"
    sleep 1
    
    # Test 3: JavaScript for Automation (JXA)
    print_test "JavaScript for Automation execution (T1059.007)"
    osascript -l JavaScript -e 'var app = Application.currentApplication(); app.includeStandardAdditions = true; "SOC Test"' 2>/dev/null || true
    print_expected "Rule 200211 - JXA execution"
    sleep 1
    
    log "Execution tests completed"
}

# =============================================================================
# CREDENTIAL ACCESS SIMULATIONS
# =============================================================================

test_credential_access() {
    print_section "CREDENTIAL ACCESS TECHNIQUES (T1555)"
    
    # Test 1: Keychain enumeration (T1555.001)
    print_test "Keychain enumeration attempt (T1555.001)"
    # Safe: just lists keychains, doesn't dump credentials
    security list-keychains 2>/dev/null || true
    print_expected "Rule 200220/200221 - Keychain access"
    sleep 1
    
    # Test 2: Check for SSH keys (T1552.004)
    print_test "SSH key enumeration (T1552.004)"
    ls -la ~/.ssh/ 2>/dev/null || true
    print_expected "Rule 200224 - SSH key access"
    sleep 1
    
    # Test 3: Simulate browser credential file check
    print_test "Browser credential file discovery"
    find ~/Library/Application\ Support/Google/Chrome -name "Login Data" 2>/dev/null || echo "Chrome not installed"
    find ~/Library/Safari -name "*.plist" -maxdepth 1 2>/dev/null | head -3 || true
    print_expected "Rule 200222/200223 - Browser credential access"
    sleep 1
    
    log "Credential access tests completed"
}

# =============================================================================
# DEFENSE EVASION SIMULATIONS
# =============================================================================

test_defense_evasion() {
    print_section "DEFENSE EVASION TECHNIQUES (T1562)"
    
    # Test 1: Gatekeeper status check (T1553.001)
    print_test "Gatekeeper status check (T1553.001)"
    spctl --status 2>/dev/null || true
    print_expected "Rule 200230 - Gatekeeper check"
    sleep 1
    
    # Test 2: SIP status check (T1518.001)
    print_test "SIP status check (T1518.001)"
    csrutil status 2>/dev/null || true
    print_expected "Rule 200231 - SIP status checked"
    sleep 1
    
    # Test 3: Firewall status check
    print_test "Firewall status check"
    /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || true
    print_expected "Rule 200234 - Firewall status check"
    sleep 1
    
    # Test 4: Quarantine attribute listing
    print_test "Checking quarantine attributes (T1553.001)"
    xattr -l /Applications/*.app 2>/dev/null | head -5 || true
    print_expected "Rule 200230 - Quarantine attribute check"
    sleep 1
    
    log "Defense evasion tests completed"
}

# =============================================================================
# DISCOVERY SIMULATIONS
# =============================================================================

test_discovery() {
    print_section "DISCOVERY TECHNIQUES (T1082)"
    
    # Test 1: System information gathering (T1082)
    print_test "System profiler execution (T1082)"
    system_profiler SPHardwareDataType 2>/dev/null | head -10 || true
    print_expected "Rule 200240 - system_profiler executed"
    sleep 1
    
    # Test 2: Network configuration (T1016)
    print_test "Network configuration discovery (T1016)"
    networksetup -listallhardwareports 2>/dev/null | head -10 || true
    print_expected "Rule 200241 - Network discovery"
    sleep 1
    
    # Test 3: Directory Services enumeration (T1087.002)
    print_test "Directory Services enumeration (T1087)"
    dscl . -list /Users 2>/dev/null | head -5 || true
    print_expected "Rule 200242 - Directory Services enum"
    sleep 1
    
    # Test 4: Installed applications (T1518)
    print_test "Installed applications enumeration (T1518)"
    pkgutil --pkgs 2>/dev/null | head -5 || true
    print_expected "Rule 200243 - Application enumeration"
    sleep 1
    
    log "Discovery tests completed"
}

# =============================================================================
# COLLECTION SIMULATIONS
# =============================================================================

test_collection() {
    print_section "COLLECTION TECHNIQUES (T1113)"
    
    # Test 1: Screen capture (T1113)
    print_test "Screen capture utility (T1113)"
    # Capture to temp file, then delete
    TEMP_SCREEN="/tmp/soc_test_screen_${TIMESTAMP}.png"
    screencapture -x "$TEMP_SCREEN" 2>/dev/null || true
    rm -f "$TEMP_SCREEN"
    print_expected "Rule 200250 - Screen capture"
    echo -e "    ${GREEN}✓${NC} Temporary screenshot removed"
    sleep 1
    
    # Test 2: Clipboard access (T1115)
    print_test "Clipboard access (T1115)"
    echo "SOC Test Data" | pbcopy
    pbpaste > /dev/null 2>&1 || true
    print_expected "Rule 200251 - Clipboard access"
    sleep 1
    
    # Test 3: Find sensitive files (T1083)
    print_test "Searching for sensitive files (T1083)"
    find /tmp -name "*.pem" -o -name "*.key" 2>/dev/null | head -3 || true
    print_expected "Rule 200252 - Sensitive file search"
    sleep 1
    
    log "Collection tests completed"
}

# =============================================================================
# COMMAND AND CONTROL SIMULATIONS
# =============================================================================

test_command_control() {
    print_section "COMMAND & CONTROL TECHNIQUES (T1071)"
    
    # Test 1: SSH tunnel syntax check (T1572)
    print_test "SSH tunnel command syntax (T1572)"
    echo "Would execute: ssh -D 8080 user@host (not actually connecting)"
    print_expected "Rule 200260 - SSH tunnel"
    sleep 1
    
    # Test 2: Check for nc/netcat (T1095)
    print_test "Checking for network tools (T1095)"
    which nc ncat netcat 2>/dev/null || echo "Standard network tools not found"
    print_expected "Rule 200261 - Network tool presence"
    sleep 1
    
    log "C2 tests completed"
}

# =============================================================================
# REPORT GENERATION
# =============================================================================

generate_report() {
    print_section "TEST REPORT"
    
    REPORT_FILE="${LOG_DIR}/macos_attack_report_${TIMESTAMP}.md"
    
    cat > "$REPORT_FILE" << EOF
# macOS Attack Simulation Report

**Date**: $(date '+%Y-%m-%d %H:%M:%S')
**Host**: $(hostname)
**macOS Version**: $(sw_vers -productVersion)
**User**: $(whoami)

## Tests Executed

### Persistence (T1543)
- [x] Launch Agent creation
- [x] Login Items access

### Execution (T1059)
- [x] osascript execution
- [x] osascript with shell
- [x] JavaScript for Automation

### Credential Access (T1555)
- [x] Keychain enumeration
- [x] SSH key access
- [x] Browser credential discovery

### Defense Evasion (T1562)
- [x] Gatekeeper status
- [x] SIP status
- [x] Firewall status
- [x] Quarantine attributes

### Discovery (T1082)
- [x] System profiler
- [x] Network configuration
- [x] Directory Services
- [x] Installed applications

### Collection (T1113)
- [x] Screen capture
- [x] Clipboard access
- [x] Sensitive file search

### Command & Control (T1071)
- [x] SSH tunnel syntax
- [x] Network tool check

## Expected Alerts

Check your Wazuh dashboard for the following rule IDs:
- 200200-200204: Persistence
- 200210-200213: Execution
- 200220-200224: Credential Access
- 200230-200234: Defense Evasion
- 200240-200243: Discovery
- 200250-200252: Collection
- 200260-200262: Command & Control

## Log File
Full execution log: ${LOG_FILE}

---
Generated by Cloud SOC Platform macOS Attack Simulation Suite
EOF
    
    echo -e "${GREEN}✓${NC} Report generated: ${REPORT_FILE}"
    log "Report generated: ${REPORT_FILE}"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    print_banner
    
    safety_check
    
    echo ""
    echo "Starting macOS attack simulations..."
    echo "Log file: ${LOG_FILE}"
    echo ""
    
    # Run all tests
    test_persistence
    test_execution
    test_credential_access
    test_defense_evasion
    test_discovery
    test_collection
    test_command_control
    
    # Generate report
    generate_report
    
    print_section "SIMULATION COMPLETE"
    echo -e "${GREEN}All macOS attack simulations completed successfully!${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Check Wazuh dashboard for generated alerts"
    echo "  2. Review the report: ${REPORT_FILE}"
    echo "  3. Validate detection coverage"
    echo ""
    
    log "All tests completed successfully"
}

# Run main function
main "$@"
