#!/bin/bash
# =============================================================================
# APT29 Full Kill Chain Simulation
# Cloud SOC Platform - Purple Team Testing
# =============================================================================
#
# PURPOSE: Orchestrate a complete APT29 (Cozy Bear) intrusion lifecycle,
#          running discovery → credential harvest → lateral movement →
#          C2 setup → data staging → exfiltration in sequence.
#
# This creates a realistic attack timeline for:
#   - Correlation testing across SIEM detection rules
#   - Anomaly detector pattern validation (beacons + DNS exfil)
#   - Incident response playbook exercises
#   - SOC analyst training scenarios
#
# WARNING: FOR AUTHORIZED TESTING ONLY - Run only in controlled environments
#
# Kill Chain Phases:
#   Phase 1: Initial Discovery       (T1082, T1018, T1046)
#   Phase 2: Credential Harvesting   (T1003, T1552, T1555)
#   Phase 3: Lateral Movement Prep   (T1021, T1007, T1070)
#   Phase 4: C2 Establishment        (T1071.001, T1071.004)
#   Phase 5: Data Staging & Exfil    (T1074, T1048, T1567)
#
# =============================================================================

set -euo pipefail

# Source common library
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="$SCRIPT_DIR/logs/killchain_${TIMESTAMP}"
mkdir -p "$RESULTS_DIR"

# Phase timing (seconds between phases for realistic timeline)
PHASE_DELAY=${PHASE_DELAY:-15}

# =============================================================================
# PHASE RUNNER
# =============================================================================

run_phase() {
    local phase_num=$1
    local phase_name=$2
    local script=$3
    local log_file="$RESULTS_DIR/phase${phase_num}_${script%.sh}.log"

    echo ""
    echo -e "${RED}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  PHASE ${phase_num}: ${phase_name}${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    local start_time=$(date +%s)

    if [ -f "$SCRIPT_DIR/$script" ]; then
        set +e
        echo "yes" | bash "$SCRIPT_DIR/$script" 2>&1 | tee "$log_file"
        local exit_code=${PIPESTATUS[1]}
        set -e

        local end_time=$(date +%s)
        local duration=$((end_time - start_time))

        if [ $exit_code -eq 0 ]; then
            echo -e "${GREEN}✓ Phase ${phase_num} completed in ${duration}s${NC}"
            echo "PASS|${duration}s" > "$RESULTS_DIR/phase${phase_num}.status"
        else
            echo -e "${RED}✗ Phase ${phase_num} failed (exit: $exit_code) in ${duration}s${NC}"
            echo "FAIL|${duration}s" > "$RESULTS_DIR/phase${phase_num}.status"
        fi
    else
        echo -e "${YELLOW}⚠ Script not found: $script${NC}"
        echo "SKIP|0s" > "$RESULTS_DIR/phase${phase_num}.status"
    fi

    # Delay between phases (simulates APT dwell time)
    if [ "$phase_num" -lt 5 ]; then
        echo ""
        echo -e "  ${YELLOW}⏳ Dwell time: waiting ${PHASE_DELAY}s before next phase...${NC}"
        echo -e "  ${YELLOW}   (APT29 typically waits hours/days — compressed for testing)${NC}"
        sleep "$PHASE_DELAY"
    fi
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    print_header "APT29 (Cozy Bear) Full Kill Chain Simulation"

    safety_check "a COMPLETE APT29 kill chain simulation (21 attack techniques)" "$@"

    echo ""
    echo -e "  ${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${RED}  KILL CHAIN SEQUENCE${NC}"
    echo -e "  ${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  Phase 1: ${BLUE}Discovery${NC}             → Recon the environment"
    echo -e "      │"
    echo -e "  Phase 2: ${BLUE}Credential Harvest${NC}    → Steal credentials"
    echo -e "      │"
    echo -e "  Phase 3: ${BLUE}Lateral Movement${NC}      → Spread through network"
    echo -e "      │"
    echo -e "  Phase 4: ${BLUE}C2 & Exfiltration${NC}     → Establish C2, exfil data"
    echo -e "      │"
    echo -e "  Phase 5: ${BLUE}All Linux Tests${NC}       → Privilege escalation suite"
    echo ""
    echo -e "  Phase delay: ${PHASE_DELAY}s (set PHASE_DELAY=N to change)"
    echo ""

    local global_start=$(date +%s)
    log_info "Kill chain started at $(date '+%Y-%m-%d %H:%M:%S')"
    log_info "Results directory: $RESULTS_DIR"
    echo ""

    # Execute kill chain phases
    run_phase 1 "DISCOVERY & RECONNAISSANCE"  "apt-lateral-movement.sh"
    run_phase 2 "CREDENTIAL HARVESTING"       "apt-credential-harvest.sh"
    run_phase 3 "C2 ESTABLISHMENT & EXFIL"    "apt-c2-exfil.sh"
    run_phase 4 "PRIVILEGE ESCALATION"        "privilege-escalation.sh"

    # Optional SSH brute force
    if [ -n "${SSH_TARGET_HOST:-}" ]; then
        run_phase 5 "SSH BRUTE FORCE" "ssh-brute-force.sh"
    else
        echo ""
        log_warn "Skipping SSH brute force (set SSH_TARGET_HOST to enable)"
        echo "SKIP|0s" > "$RESULTS_DIR/phase5.status"
    fi

    local global_end=$(date +%s)
    local total_duration=$((global_end - global_start))
    local minutes=$((total_duration / 60))
    local seconds=$((total_duration % 60))

    # ==========================================================================
    # KILL CHAIN REPORT
    # ==========================================================================
    local report="$RESULTS_DIR/killchain_report.md"
    cat > "$report" << EOF
# APT29 Kill Chain Simulation Report

**Date**: $(date '+%Y-%m-%d %H:%M:%S')
**Host**: $(hostname)
**User**: $(whoami)
**Duration**: ${minutes}m ${seconds}s

## Kill Chain Results

| Phase | Name | Status | Duration |
|-------|------|--------|----------|
EOF

    for i in 1 2 3 4 5; do
        if [ -f "$RESULTS_DIR/phase${i}.status" ]; then
            IFS='|' read -r status dur < "$RESULTS_DIR/phase${i}.status"
            local name=""
            case $i in
                1) name="Discovery & Recon" ;;
                2) name="Credential Harvest" ;;
                3) name="C2 & Exfiltration" ;;
                4) name="Privilege Escalation" ;;
                5) name="SSH Brute Force" ;;
            esac
            echo "| $i | $name | $status | $dur |" >> "$report"
        fi
    done

    cat >> "$report" << 'EOF'

## MITRE ATT&CK Coverage

| Tactic | Techniques |
|--------|-----------|
| Discovery | T1046, T1018, T1007, T1082, T1552.005 |
| Credential Access | T1003.008, T1552.004, T1552.003, T1552.001, T1558.003, T1555.003, T1003.007 |
| Lateral Movement | T1021.004 |
| Defense Evasion | T1070.002, T1070.006 |
| Command & Control | T1071.001, T1071.004 |
| Exfiltration | T1074.001, T1048.003, T1573.001, T1567.002 |
| Execution | T1105 |
| Privilege Escalation | T1548.003 |

## Verification Checklist
- [ ] Check Wazuh alerts (Rules 100xxx)
- [ ] Run anomaly detector — verify beacon + DNS exfil detection
- [ ] Review SIEM correlation (multiple alerts from same host in short window)
- [ ] Test incident response playbook activation
EOF

    echo ""
    print_header "KILL CHAIN COMPLETE"
    echo ""
    echo -e "  Total duration: ${minutes}m ${seconds}s"
    echo -e "  Report: $report"
    echo -e "  Logs: $RESULTS_DIR/"
    echo ""
    echo "  Verification:"
    echo "    1. Check Wazuh dashboard for correlated alerts"
    echo "    2. Run: cd ai-analyst && python3 src/detect_anomalies.py --demo"
    echo "    3. Review kill chain report: $report"
    echo ""
}

main "$@"
