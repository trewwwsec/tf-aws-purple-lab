#!/bin/bash
#
# SSH Brute Force Attack Simulation
# MITRE ATT&CK: T1110 - Brute Force
# Tests Detection Rules: 200001, 200002, 200003
#
# ⚠️  WARNING: Only run in isolated lab environment!
#

set -e

# Source common library
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

# Configuration
TARGET_HOST="${SSH_TARGET_HOST:-localhost}"
TARGET_USER="${SSH_TARGET_USER:-testuser}"
ATTEMPTS=6
DELAY=2

# Print header
print_header "SSH Brute Force Attack Simulation"
echo -e "${BLUE}MITRE ATT&CK: T1110 - Brute Force${NC}"
echo ""

# Safety check
echo "Target: $TARGET_USER@$TARGET_HOST"
echo "Attempts: $ATTEMPTS"
echo ""
safety_check "a brute force attack" $@

echo ""
log_info "Starting SSH brute force simulation..."
echo ""

# Test 1: Multiple Failed Login Attempts (Rule 200001)
echo -e "${BLUE}[TEST 1]${NC} Simulating multiple failed SSH login attempts"
echo "Expected Detection: Rule 200001 (SSH brute force - 5+ failures)"
echo "----------------------------------------"

log_info "Starting SSH brute force simulation against $TARGET_HOST"

# Create a temporary password list
TEMP_PASS_FILE=$(mktemp)
cat > "$TEMP_PASS_FILE" << EOF
wrongpass1
wrongpass2
wrongpass3
wrongpass4
wrongpass5
wrongpass6
EOF

echo "Attempting $ATTEMPTS failed logins..."

# Method 1: Using sshpass (if available)
if command -v sshpass &> /dev/null; then
    echo "Using sshpass for automated attempts..."
    
    attempt=1
    while IFS= read -r password; do
        echo -e "${YELLOW}Attempt $attempt/$ATTEMPTS:${NC} Trying password: $password"
        sshpass -p "$password" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
            "$TARGET_USER@$TARGET_HOST" "echo test" 2>&1 | grep -q "Permission denied" && \
            echo "  ✗ Failed (expected)" || echo "  ✗ Failed"
        
        log_info "Failed SSH attempt $attempt with password: $password"
        attempt=$((attempt + 1))
        sleep $DELAY
    done < "$TEMP_PASS_FILE"
    
else
    # Method 2: Manual instructions if sshpass not available
    echo -e "${YELLOW}sshpass not installed. Manual testing required.${NC}"
    echo ""
    echo "To simulate this attack manually:"
    echo "1. Run the following command $ATTEMPTS times:"
    echo "   ssh $TARGET_USER@$TARGET_HOST"
    echo "2. Enter a wrong password each time"
    echo "3. Wait $DELAY seconds between attempts"
    echo ""
    echo "Or install sshpass:"
    echo "   Ubuntu/Debian: sudo apt install sshpass"
    echo "   RHEL/CentOS: sudo yum install sshpass"
    echo "   macOS: brew install hudochenkov/sshpass/sshpass"
    echo ""
fi

# Cleanup
rm -f "$TEMP_PASS_FILE"

echo ""
echo -e "${GREEN}[✓] Test 1 Complete${NC}"
echo ""

# Test 2: Successful Login After Failures (Rule 200002)
echo -e "${BLUE}[TEST 2]${NC} Simulating successful login after failed attempts"
echo "Expected Detection: Rule 200002 (Successful login after brute force)"
echo "----------------------------------------"

if [ -n "$SSH_VALID_PASSWORD" ] || [ -n "$SSH_KEY_PATH" ]; then
    echo "Attempting successful login..."
    
    if [ -n "$SSH_KEY_PATH" ]; then
        ssh -i "$SSH_KEY_PATH" -o StrictHostKeyChecking=no "$TARGET_USER@$TARGET_HOST" "echo 'Successful login'" && \
            echo -e "${GREEN}✓ Successful login (this should trigger Rule 200002)${NC}" || \
            echo -e "${RED}✗ Login failed${NC}"
    else
        echo "Using password authentication..."
        sshpass -p "$SSH_VALID_PASSWORD" ssh -o StrictHostKeyChecking=no "$TARGET_USER@$TARGET_HOST" "echo 'Successful login'" && \
            echo -e "${GREEN}✓ Successful login (this should trigger Rule 200002)${NC}" || \
            echo -e "${RED}✗ Login failed${NC}"
    fi
    
    log_info "Successful SSH login after failed attempts"
else
    echo -e "${YELLOW}⚠ Skipping Test 2: No valid credentials provided${NC}"
    echo "To test Rule 200002, set one of:"
    echo "  export SSH_VALID_PASSWORD='your_password'"
    echo "  export SSH_KEY_PATH='/path/to/key.pem'"
fi

echo ""
echo -e "${GREEN}[✓] Test 2 Complete${NC}"
echo ""

# Test 3: Off-Hours Login (Rule 200003)
echo -e "${BLUE}[TEST 3]${NC} Off-hours login detection"
echo "Expected Detection: Rule 200003 (Login during unusual hours 2 AM - 6 AM)"
echo "----------------------------------------"

current_hour=$(date +%H)
if [ "$current_hour" -ge 2 ] && [ "$current_hour" -lt 6 ]; then
    echo -e "${YELLOW}Current time is within off-hours window (2 AM - 6 AM)${NC}"
    echo "Any successful login now will trigger Rule 200003"
else
    echo -e "${YELLOW}Current time ($current_hour:00) is NOT in off-hours window${NC}"
    echo "Rule 200003 only triggers between 2 AM - 6 AM"
    echo "To test this rule, run this script during those hours"
fi

echo ""
echo -e "${GREEN}[✓] Test 3 Complete${NC}"
echo ""

# Summary
print_header "SIMULATION SUMMARY"
echo "Simulation Type: SSH Brute Force"
echo "MITRE ATT&CK: T1110 - Brute Force"
echo "Target: $TARGET_USER@$TARGET_HOST"
echo "Failed Attempts: $ATTEMPTS"
echo ""
echo "Expected Wazuh Alerts:"
echo "  • Rule 200001: SSH brute force (5+ failures in 2 minutes)"
echo "  • Rule 200002: Successful login after failures (if credentials provided)"
echo "  • Rule 200003: Off-hours login (if during 2 AM - 6 AM)"
echo ""
print_section "📋" "Verification Steps"
echo "1. Check Wazuh dashboard for alerts"
echo "2. Or run on Wazuh server:"
echo "   sudo tail -n 100 /var/ossec/logs/alerts/alerts.log | grep '200001\|200002\|200003'"
echo ""
echo "Simulation Type: SSH Brute Force"
echo "MITRE ATT&CK: T1110 - Brute Force"
echo "Target: $TARGET_USER@$TARGET_HOST"
echo "Failed Attempts: $ATTEMPTS"
echo ""
echo "Expected Wazuh Alerts:"
echo "  • Rule 200001: SSH brute force (5+ failures in 2 minutes)"
echo "  • Rule 200002: Successful login after failures (if credentials provided)"
echo "  • Rule 200003: Off-hours login (if during 2 AM - 6 AM)"
echo ""
echo -e "${GREEN}Verification Steps:${NC}"
echo "1. Check Wazuh dashboard for alerts"
echo "2. Or run on Wazuh server:"
echo "   sudo tail -n 100 /var/ossec/logs/alerts/alerts.log | grep '200001\\|200002\\|200003'"
echo ""
echo "Log file: simulation.log"
echo ""

# Verification helper
echo ""
read -p "Would you like to check for alerts now? (yes/no): " check_alerts

if [ "$check_alerts" = "yes" ]; then
    check_wazuh_alerts "200001\|200002\|200003"
fi

echo ""
log_info "SSH Brute Force Simulation Complete!"
echo ""
