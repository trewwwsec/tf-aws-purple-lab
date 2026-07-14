#!/bin/bash
#
# Detection Rule Testing Framework
# Tests all custom Wazuh detection rules
# Usage: ./test-detections.sh [rule_id]
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
WAZUH_SERVER="${WAZUH_SERVER:-localhost}"
ALERT_LOG="/var/ossec/logs/alerts/alerts.log"
TEST_RESULTS_DIR="./test-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REMOTE_MODE=false

# Detect if running remotely (WAZUH_SERVER is not localhost and SSH is available)
if [ "$WAZUH_SERVER" != "localhost" ] && command -v ssh &> /dev/null; then
    REMOTE_MODE=true
    echo -e "${BLUE}Remote mode: executing on $WAZUH_SERVER via SSH${NC}"
fi

# Wrapper for alert log access (local or remote)
get_alert_tail() {
    local lines=${1:-50}
    if [ "$REMOTE_MODE" = true ]; then
        ssh "$WAZUH_SERVER" "sudo tail -n $lines $ALERT_LOG"
    else
        sudo tail -n "$lines" "$ALERT_LOG"
    fi
}

get_alert_grep() {
    local rule_id=$1
    local lines=${2:-200}
    if [ "$REMOTE_MODE" = true ]; then
        ssh "$WAZUH_SERVER" "sudo tail -n $lines $ALERT_LOG | grep 'Rule: $rule_id'"
    else
        sudo tail -n "$lines" "$ALERT_LOG" | grep "Rule: $rule_id"
    fi
}

# Create results directory
mkdir -p "$TEST_RESULTS_DIR"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Detection Rule Testing Framework${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Function to print test header
print_test_header() {
    echo -e "\n${YELLOW}[TEST]${NC} $1"
    echo "----------------------------------------"
}

# Function to check if alert was generated
check_alert() {
    local rule_id=$1
    local timeout=${2:-10}
    local start_time=$(date +%s)
    
    echo -e "Waiting for alert (Rule ID: ${rule_id}, Timeout: ${timeout}s)..."
    
    while [ $(($(date +%s) - start_time)) -lt $timeout ]; do
        if get_alert_grep "$rule_id" 50 | grep -q "Rule: $rule_id"; then
            echo -e "${GREEN}✓ Alert detected!${NC}"
            get_alert_tail 20 | grep -A 10 "Rule: $rule_id" | head -15
            return 0
        fi
        sleep 1
    done
    
    echo -e "${RED}✗ Alert NOT detected within ${timeout}s${NC}"
    return 1
}

# Function to test SSH brute force (Rule 200001)
test_ssh_brute_force() {
    print_test_header "SSH Brute Force Detection (Rule 200001)"
    
    echo "Simulating 6 failed SSH login attempts..."
    
    # Note: This requires a target SSH server
    if [ -z "$SSH_TARGET" ]; then
        echo -e "${YELLOW}⚠ SSH_TARGET not set. Skipping live test.${NC}"
        echo "To run this test: export SSH_TARGET=user@host"
        return 0
    fi
    
    for i in {1..6}; do
        echo "Attempt $i/6..."
        sshpass -p "wrongpassword" ssh -o StrictHostKeyChecking=no "$SSH_TARGET" 2>/dev/null || true
        sleep 1
    done
    
    check_alert "200001" 15
}

# Function to test PowerShell encoded command (Rule 200010)
test_powershell_encoded() {
    print_test_header "PowerShell Encoded Command (Rule 200010)"
    
    if [ -z "$WINDOWS_TARGET" ]; then
        echo -e "${YELLOW}⚠ WINDOWS_TARGET not set. Showing test command.${NC}"
        echo ""
        echo "Run this on Windows endpoint:"
        echo '  $cmd = "Write-Host Test"'
        echo '  $bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)'
        echo '  $encoded = [Convert]::ToBase64String($bytes)'
        echo '  powershell.exe -EncodedCommand $encoded'
        echo ""
        echo "Then check for alert..."
        return 0
    fi
    
    # If WinRM is configured, execute remotely
    echo "Executing encoded PowerShell command on $WINDOWS_TARGET..."
    # Add WinRM execution here if configured
    
    check_alert "200010" 15
}

# Function to test sudo abuse (Rule 200021)
test_sudo_abuse() {
    print_test_header "Sudo Abuse Detection (Rule 200021)"
    
    if [ -z "$LINUX_TARGET" ]; then
        echo "Testing on local system..."
        LINUX_TARGET="localhost"
    fi
    
    echo "Executing suspicious sudo command..."
    
    if [ "$LINUX_TARGET" = "localhost" ]; then
        sudo bash -c "echo 'Detection test - Rule 200021'" || true
    else
        ssh "$LINUX_TARGET" "sudo bash -c 'echo Detection test'" || true
    fi
    
    check_alert "200021" 15
}

# Function to test file integrity monitoring (Rule 200050)
test_file_integrity() {
    print_test_header "File Integrity Monitoring (Rule 200050)"
    
    if [ -z "$LINUX_TARGET" ]; then
        echo "Testing on local system..."
        LINUX_TARGET="localhost"
    fi
    
    echo "Modifying /etc/hosts (will be reverted)..."
    
    if [ "$LINUX_TARGET" = "localhost" ]; then
        # Backup
        sudo cp /etc/hosts /etc/hosts.backup.test
        # Modify
        echo "# Test modification for detection" | sudo tee -a /etc/hosts > /dev/null
        sleep 2
        # Restore
        sudo mv /etc/hosts.backup.test /etc/hosts
    else
        ssh "$LINUX_TARGET" "sudo cp /etc/hosts /etc/hosts.backup.test && \
                             echo '# Test' | sudo tee -a /etc/hosts && \
                             sleep 2 && \
                             sudo mv /etc/hosts.backup.test /etc/hosts" || true
    fi
    
    check_alert "200050" 15
}

# Function to test user creation (Rule 200030)
test_user_creation() {
    print_test_header "User Creation Detection (Rule 200030)"
    
    if [ -z "$LINUX_TARGET" ]; then
        echo "Testing on local system..."
        LINUX_TARGET="localhost"
    fi
    
    echo "Creating and removing test user..."
    
    if [ "$LINUX_TARGET" = "localhost" ]; then
        sudo useradd testdetection || true
        sleep 2
        sudo userdel testdetection || true
    else
        ssh "$LINUX_TARGET" "sudo useradd testdetection && sleep 2 && sudo userdel testdetection" || true
    fi
    
    check_alert "200030" 15
}

# Function to test cron job creation (Rule 200060)
test_cron_persistence() {
    print_test_header "Cron Job Persistence (Rule 200060)"
    
    if [ -z "$LINUX_TARGET" ]; then
        echo "Testing on local system..."
        LINUX_TARGET="localhost"
    fi
    
    echo "Creating and removing test cron job..."
    
    if [ "$LINUX_TARGET" = "localhost" ]; then
        # Add cron job
        (crontab -l 2>/dev/null; echo "# Test detection") | crontab -
        sleep 2
        # Remove test line
        crontab -l | grep -v "# Test detection" | crontab -
    else
        ssh "$LINUX_TARGET" "(crontab -l 2>/dev/null; echo '# Test') | crontab - && \
                             sleep 2 && \
                             crontab -l | grep -v '# Test' | crontab -" || true
    fi
    
    check_alert "200060" 15
}

# Function to generate test report
generate_report() {
    local report_file="$TEST_RESULTS_DIR/test_report_$TIMESTAMP.txt"
    
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE}  Generating Test Report${NC}"
    echo -e "${BLUE}========================================${NC}"
    
    {
        echo "Detection Rule Test Report"
        echo "Generated: $(date)"
        echo "Wazuh Server: $WAZUH_SERVER"
        echo ""
        echo "Test Results:"
        echo "----------------------------------------"
        
        # Count alerts generated in last 10 minutes
        local recent_alerts=$(get_alert_grep "200" 1000 | wc -l || echo "0")
        echo "Total alerts generated: $recent_alerts"
        
        echo ""
        echo "Alerts by Rule ID:"
        get_alert_grep "200" 1000 | awk '{print $7}' | sort | uniq -c || true
        
    } | tee "$report_file"
    
    echo -e "\n${GREEN}Report saved to: $report_file${NC}"
}

# Function to run all tests
run_all_tests() {
    echo -e "${BLUE}Running all detection tests...${NC}\n"
    
    local tests=(
        "test_sudo_abuse"
        "test_file_integrity"
        "test_user_creation"
        "test_cron_persistence"
        "test_ssh_brute_force"
        "test_powershell_encoded"
    )
    
    for test in "${tests[@]}"; do
        $test || echo -e "${YELLOW}⚠ Test failed or skipped${NC}"
        echo ""
        sleep 2
    done
    
    generate_report
}

# Function to monitor alerts in real-time
monitor_alerts() {
    print_test_header "Real-time Alert Monitoring"
    
    echo "Monitoring alerts for custom rules (200xxx)..."
    echo "Press Ctrl+C to stop"
    echo ""
    
    if [ "$REMOTE_MODE" = true ]; then
        ssh "$WAZUH_SERVER" "sudo tail -f $ALERT_LOG | grep --line-buffered 'Rule: 200'"
    else
        sudo tail -f "$ALERT_LOG" | grep --line-buffered "Rule: 200" | while read -r line; do
            echo -e "${GREEN}[ALERT]${NC} $line"
        done
    fi
}

# Function to show usage
show_usage() {
    cat << EOF
Detection Rule Testing Framework

Usage: $0 [command]

Commands:
    all                 Run all detection tests
    ssh                 Test SSH brute force detection
    powershell          Test PowerShell abuse detection
    sudo                Test sudo abuse detection
    file                Test file integrity monitoring
    user                Test user creation detection
    cron                Test cron persistence detection
    monitor             Monitor alerts in real-time
    report              Generate test report
    help                Show this help message

Environment Variables:
    WAZUH_SERVER        Wazuh server hostname/IP (default: localhost)
    SSH_TARGET          SSH target for brute force test (user@host)
    WINDOWS_TARGET      Windows target for PowerShell tests
    LINUX_TARGET        Linux target for tests (default: localhost)

Examples:
    # Run all tests
    $0 all

    # Test specific detection
    $0 sudo

    # Monitor alerts
    $0 monitor

    # Test SSH brute force with target
    export SSH_TARGET=ubuntu@10.0.2.155
    $0 ssh

EOF
}

# Main script logic
case "${1:-help}" in
    all)
        run_all_tests
        ;;
    ssh)
        test_ssh_brute_force
        ;;
    powershell)
        test_powershell_encoded
        ;;
    sudo)
        test_sudo_abuse
        ;;
    file)
        test_file_integrity
        ;;
    user)
        test_user_creation
        ;;
    cron)
        test_cron_persistence
        ;;
    monitor)
        monitor_alerts
        ;;
    report)
        generate_report
        ;;
    help|--help|-h)
        show_usage
        ;;
    *)
        echo -e "${RED}Unknown command: $1${NC}"
        echo ""
        show_usage
        exit 1
        ;;
esac

echo -e "\n${GREEN}Done!${NC}"
