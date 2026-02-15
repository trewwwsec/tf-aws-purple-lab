#!/bin/bash
#
# Run All Linux Attack Simulations
# Orchestrates all Linux-based attack simulations
#
# ⚠️  WARNING: Only run in isolated lab environment!
#

set -e

# Source common library
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

# Print header
print_header "Cloud SOC - Attack Simulation Suite"

# Safety check
safety_check "ALL attack simulations (multiple security alerts)"

# Create results directory
RESULTS_DIR="$SCRIPT_DIR/results/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

echo ""
log_info "Starting attack simulation suite..."
log_info "Results will be saved to: $RESULTS_DIR"
echo ""

# Function to run simulation
run_simulation() {
    local script_name=$1
    local description=$2
    local log_file="$RESULTS_DIR/${script_name%.sh}.log"
    
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║ Running: $description${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    if [ -f "$SCRIPT_DIR/$script_name" ]; then
        # Run with automatic yes confirmation
        # Disable exit on error temporarily to capture exit code
        set +e
        echo "yes" | bash "$SCRIPT_DIR/$script_name" 2>&1 | tee "$log_file"
        exit_code=${PIPESTATUS[1]}
        set -e
        
        if [ $exit_code -eq 0 ]; then
            echo -e "${GREEN}✓ $description completed successfully${NC}"
            echo "PASS" > "$RESULTS_DIR/${script_name%.sh}.status"
        else
            echo -e "${RED}✗ $description failed (exit code: $exit_code)${NC}"
            echo "FAIL" > "$RESULTS_DIR/${script_name%.sh}.status"
        fi
    else
        echo -e "${YELLOW}⚠ Script not found: $script_name${NC}"
        echo "SKIP" > "$RESULTS_DIR/${script_name%.sh}.status"
    fi
    
    echo ""
    echo "Waiting 10 seconds before next simulation..."
    sleep 10
    echo ""
}

# Track start time
START_TIME=$(date +%s)

# Run simulations
run_simulation "privilege-escalation.sh" "Privilege Escalation (T1548.003)"

# APT Red Team Simulations
run_simulation "apt-credential-harvest.sh" "APT Credential Harvesting (T1003, T1552, T1555)"
run_simulation "apt-lateral-movement.sh" "APT Lateral Movement & Discovery (T1046, T1018, T1070)"
run_simulation "apt-c2-exfil.sh" "APT C2 & Data Exfiltration (T1071, T1048, T1567)"

# Note: SSH brute force requires external target, skip if not configured
if [ -n "$SSH_TARGET_HOST" ]; then
    run_simulation "ssh-brute-force.sh" "SSH Brute Force (T1110)"
else
    log_warn "SSH_TARGET_HOST not set, skipping SSH brute force"
    echo "To enable: export SSH_TARGET_HOST='target.example.com'"
    echo "SKIP" > "$RESULTS_DIR/ssh-brute-force.status"
fi

# Calculate duration
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
MINUTES=$((DURATION / 60))
SECONDS=$((DURATION % 60))

# Generate summary report
REPORT_FILE="$RESULTS_DIR/summary-report.txt"

cat > "$REPORT_FILE" << EOF
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║        Attack Simulation Suite - Summary Report         ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝

Execution Date: $(date '+%Y-%m-%d %H:%M:%S')
Duration: ${MINUTES}m ${SECONDS}s
Results Directory: $RESULTS_DIR

═══════════════════════════════════════════════════════════
SIMULATION RESULTS
═══════════════════════════════════════════════════════════

EOF

# Count results
TOTAL=0
PASSED=0
FAILED=0
SKIPPED=0

for status_file in "$RESULTS_DIR"/*.status; do
    if [ -f "$status_file" ]; then
        TOTAL=$((TOTAL + 1))
        status=$(cat "$status_file")
        sim_name=$(basename "$status_file" .status)
        
        case $status in
            PASS)
                PASSED=$((PASSED + 1))
                echo "✓ $sim_name - PASSED" >> "$REPORT_FILE"
                ;;
            FAIL)
                FAILED=$((FAILED + 1))
                echo "✗ $sim_name - FAILED" >> "$REPORT_FILE"
                ;;
            SKIP)
                SKIPPED=$((SKIPPED + 1))
                echo "⊘ $sim_name - SKIPPED" >> "$REPORT_FILE"
                ;;
        esac
    fi
done

cat >> "$REPORT_FILE" << EOF

═══════════════════════════════════════════════════════════
STATISTICS
═══════════════════════════════════════════════════════════

Total Simulations: $TOTAL
Passed: $PASSED
Failed: $FAILED
Skipped: $SKIPPED
Success Rate: $(( TOTAL > 0 ? (PASSED * 100) / TOTAL : 0 ))%

═══════════════════════════════════════════════════════════
EXPECTED WAZUH ALERTS
═══════════════════════════════════════════════════════════

The following detection rules should have triggered:

Privilege Escalation:
  • Rule 100020: Sudo command executed
  • Rule 100021: Suspicious sudo command
  • Rule 100022: Root shell escalation
  • Rule 100032: Privileged group modification

SSH Brute Force (if executed):
  • Rule 100001: SSH brute force attack
  • Rule 100002: Successful login after failures
  • Rule 100003: Off-hours login

═══════════════════════════════════════════════════════════
VERIFICATION STEPS
═══════════════════════════════════════════════════════════

1. Check Wazuh Dashboard:
   Navigate to Security Events and filter by Rule IDs: 100*

2. Query via Command Line (on Wazuh server):
   sudo tail -n 200 /var/ossec/logs/alerts/alerts.log | grep "Rule: 100"

3. Generate Alert Report:
   sudo grep "Rule: 100" /var/ossec/logs/alerts/alerts.log | \
     awk '{print \$7}' | sort | uniq -c

4. Review Individual Logs:
   Each simulation log is in: $RESULTS_DIR/

═══════════════════════════════════════════════════════════
NEXT STEPS
═══════════════════════════════════════════════════════════

1. Verify all expected alerts were generated
2. Document any false negatives (missed detections)
3. Tune detection rules if necessary
4. Create incident reports for practice
5. Update response playbooks based on findings

═══════════════════════════════════════════════════════════
EOF

# Display summary
echo ""
print_header "SIMULATION COMPLETE"
echo ""
cat "$REPORT_FILE"
echo ""

# Offer to check Wazuh alerts
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}Would you like to check Wazuh server for alerts?${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
read -p "Check alerts? (yes/no): " check_alerts

if [ "$check_alerts" = "yes" ]; then
    if [ -z "$WAZUH_SERVER" ]; then
        read -p "Enter Wazuh server (e.g., ubuntu@10.0.1.100): " WAZUH_SERVER
    fi
    
    if [ -n "$WAZUH_SERVER" ]; then
        echo ""
        log_info "Connecting to Wazuh server..."
        echo ""
        
        ssh "$WAZUH_SERVER" << 'ENDSSH'
echo "Recent alerts from attack simulations:"
echo "======================================="
sudo tail -n 200 /var/ossec/logs/alerts/alerts.log | grep "Rule: 100" | tail -20

echo ""
echo "Alert summary by Rule ID:"
echo "========================="
sudo grep "Rule: 100" /var/ossec/logs/alerts/alerts.log | \
  awk '{print $7}' | sort | uniq -c | sort -rn
ENDSSH
    fi
fi

echo ""
log_info "Attack Simulation Suite Complete!"
log_info "Results saved to: $RESULTS_DIR"
echo ""
