#!/bin/bash
# =============================================================================
# APT29 Multi-Victim Kill Chain Orchestrator
# Cloud SOC Platform - Purple Team Testing
# =============================================================================
#
# PURPOSE: Orchestrate a complete APT29 (Cozy Bear) intrusion across multiple
#          victim machines — Linux, macOS, and Windows — from a central
#          attack platform via SSH/PSRemoting.
#
# USAGE:
#   # Define targets (comma-separated user@host)
#   export LINUX_TARGETS="ubuntu@10.0.2.100,ubuntu@10.0.2.101"
#   export MACOS_TARGETS="admin@10.0.3.50"
#   export WINDOWS_TARGETS="administrator@10.0.4.200"
#
#   # Run kill chain against all targets
#   ./apt-full-killchain.sh
#
#   # Run against specific platform only
#   ./apt-full-killchain.sh --linux-only
#   ./apt-full-killchain.sh --macos-only
#
#   # Use config file instead of env vars
#   ./apt-full-killchain.sh --config targets.conf
#
# CONFIG FILE FORMAT (targets.conf):
#   LINUX_TARGETS=ubuntu@10.0.2.100,ubuntu@10.0.2.101
#   MACOS_TARGETS=admin@10.0.3.50
#   WINDOWS_TARGETS=administrator@10.0.4.200
#
# WARNING: FOR AUTHORIZED TESTING ONLY
#
# Kill Chain Phases:
#   Phase 1: Deploy payloads to all targets
#   Phase 2: Discovery & Reconnaissance (all platforms)
#   Phase 3: Credential Harvesting (all platforms)
#   Phase 4: C2 Establishment & Exfiltration (Linux/macOS)
#   Phase 5: Privilege Escalation (Linux)
#   Phase 6: Collect results from all targets
#
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="$SCRIPT_DIR/logs/killchain_${TIMESTAMP}"
REMOTE_WORKDIR="/tmp/soc-killchain-${TIMESTAMP}"
mkdir -p "$RESULTS_DIR"

# Phase timing (seconds between phases)
PHASE_DELAY=${PHASE_DELAY:-10}

# SSH options for non-interactive execution
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes"

# =============================================================================
# ARGUMENT PARSING
# =============================================================================

LINUX_ONLY=false
MACOS_ONLY=false
WINDOWS_ONLY=false
CONFIG_FILE=""

parse_args() {
    for arg in "$@"; do
        case "$arg" in
            --linux-only)   LINUX_ONLY=true ;;
            --macos-only)   MACOS_ONLY=true ;;
            --windows-only) WINDOWS_ONLY=true ;;
            --config=*)     CONFIG_FILE="${arg#*=}" ;;
            --config)       shift; CONFIG_FILE="$1" ;;
            --force|-f|-y)  ;; # handled by safety_check
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --linux-only      Only attack Linux targets"
                echo "  --macos-only      Only attack macOS targets"
                echo "  --windows-only    Only attack Windows targets"
                echo "  --config=FILE     Load targets from config file"
                echo "  --force, -f, -y   Skip safety confirmation"
                echo ""
                echo "Environment variables:"
                echo "  LINUX_TARGETS     Comma-separated list of user@host"
                echo "  MACOS_TARGETS     Comma-separated list of user@host"
                echo "  WINDOWS_TARGETS   Comma-separated list of user@host"
                echo "  PHASE_DELAY       Seconds between phases (default: 10)"
                exit 0
                ;;
        esac
    done

    # Load config file if specified
    if [ -n "$CONFIG_FILE" ] && [ -f "$CONFIG_FILE" ]; then
        log_info "Loading targets from: $CONFIG_FILE"
        # shellcheck disable=SC1090
        source "$CONFIG_FILE"
    fi
}

# =============================================================================
# TARGET MANAGEMENT
# =============================================================================

# Parse comma-separated targets into an array
get_targets() {
    local targets_str="$1"
    IFS=',' read -ra targets <<< "$targets_str"
    echo "${targets[@]}"
}

# Test SSH connectivity to a target
test_connection() {
    local target=$1
    ssh $SSH_OPTS "$target" "echo OK" 2>/dev/null
}

# Validate all targets are reachable
validate_targets() {
    local platform=$1
    local targets_str=$2
    local reachable=0
    local unreachable=0

    for target in $(get_targets "$targets_str"); do
        echo -ne "    Testing ${target}..."
        if test_connection "$target" | grep -q "OK"; then
            echo -e " ${GREEN}✓${NC}"
            reachable=$((reachable + 1))
        else
            echo -e " ${RED}✗ unreachable${NC}"
            unreachable=$((unreachable + 1))
        fi
    done

    echo -e "    ${platform}: ${reachable} reachable, ${unreachable} unreachable"
    return $unreachable
}

# =============================================================================
# REMOTE EXECUTION
# =============================================================================

# Deploy scripts to a remote target
deploy_scripts() {
    local target=$1
    local platform=$2  # linux, macos, windows

    echo -e "  ${YELLOW}▸${NC} Deploying to ${target}..."

    # Create remote work directory
    ssh $SSH_OPTS "$target" "mkdir -p $REMOTE_WORKDIR" 2>/dev/null || return 1

    # Always deploy common.sh
    scp $SSH_OPTS "$SCRIPT_DIR/common.sh" "${target}:${REMOTE_WORKDIR}/" 2>/dev/null || return 1

    case "$platform" in
        linux)
            scp $SSH_OPTS \
                "$SCRIPT_DIR/apt-credential-harvest.sh" \
                "$SCRIPT_DIR/apt-lateral-movement.sh" \
                "$SCRIPT_DIR/apt-c2-exfil.sh" \
                "$SCRIPT_DIR/privilege-escalation.sh" \
                "${target}:${REMOTE_WORKDIR}/" 2>/dev/null || return 1
            ;;
        macos)
            scp $SSH_OPTS \
                "$SCRIPT_DIR/apt-credential-harvest.sh" \
                "$SCRIPT_DIR/apt-lateral-movement.sh" \
                "$SCRIPT_DIR/apt-c2-exfil.sh" \
                "$SCRIPT_DIR/macos-attacks.sh" \
                "${target}:${REMOTE_WORKDIR}/" 2>/dev/null || return 1
            ;;
        windows)
            scp $SSH_OPTS \
                "$SCRIPT_DIR/powershell-attacks.ps1" \
                "${target}:${REMOTE_WORKDIR}/" 2>/dev/null || return 1
            ;;
    esac

    # Make scripts executable
    ssh $SSH_OPTS "$target" "chmod +x ${REMOTE_WORKDIR}/*.sh 2>/dev/null" || true
    echo -e "    ${GREEN}✓${NC} Deployed to ${target}"
}

# Run a script on a remote target
run_remote() {
    local target=$1
    local script=$2
    local description=$3
    local log_file="$RESULTS_DIR/${target//[@:.]/_}_${script%.sh}.log"

    echo -e "  ${BLUE}▸${NC} [${target}] ${description}"

    local start_time=$(date +%s)
    set +e
    ssh $SSH_OPTS "$target" "cd ${REMOTE_WORKDIR} && echo yes | bash ./${script} --force" \
        2>&1 | tee "$log_file"
    local exit_code=$?
    set -e
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    if [ $exit_code -eq 0 ]; then
        echo -e "    ${GREEN}✓${NC} Completed in ${duration}s"
        echo "PASS|${duration}s|${target}" >> "$RESULTS_DIR/phase_results.log"
    else
        echo -e "    ${RED}✗${NC} Failed (exit: $exit_code) in ${duration}s"
        echo "FAIL|${duration}s|${target}" >> "$RESULTS_DIR/phase_results.log"
    fi
}

# Run PowerShell script on Windows target via SSH
run_remote_windows() {
    local target=$1
    local script=$2
    local description=$3
    local log_file="$RESULTS_DIR/${target//[@:.]/_}_${script%.ps1}.log"

    echo -e "  ${BLUE}▸${NC} [${target}] ${description}"

    local start_time=$(date +%s)
    set +e
    ssh $SSH_OPTS "$target" "powershell.exe -ExecutionPolicy Bypass -File ${REMOTE_WORKDIR}/${script}" \
        2>&1 | tee "$log_file"
    local exit_code=$?
    set -e
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    if [ $exit_code -eq 0 ]; then
        echo -e "    ${GREEN}✓${NC} Completed in ${duration}s"
        echo "PASS|${duration}s|${target}" >> "$RESULTS_DIR/phase_results.log"
    else
        echo -e "    ${RED}✗${NC} Failed (exit: $exit_code) in ${duration}s"
        echo "FAIL|${duration}s|${target}" >> "$RESULTS_DIR/phase_results.log"
    fi
}

# Cleanup remote artifacts from a target
cleanup_remote() {
    local target=$1
    echo -ne "    Cleaning ${target}..."
    ssh $SSH_OPTS "$target" "rm -rf ${REMOTE_WORKDIR}" 2>/dev/null && \
        echo -e " ${GREEN}✓${NC}" || echo -e " ${YELLOW}⚠${NC}"
}

# =============================================================================
# KILL CHAIN PHASES
# =============================================================================

phase_header() {
    local phase_num=$1
    local phase_name=$2
    echo ""
    echo -e "${RED}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  PHASE ${phase_num}: ${phase_name}${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

phase_delay() {
    if [ "$PHASE_DELAY" -gt 0 ]; then
        echo ""
        echo -e "  ${YELLOW}⏳ Dwell time: ${PHASE_DELAY}s before next phase...${NC}"
        sleep "$PHASE_DELAY"
    fi
}

# Phase 1: Deploy scripts to all targets
phase_deploy() {
    phase_header 1 "PAYLOAD DEPLOYMENT"

    if [ -n "${LINUX_TARGETS:-}" ] && [ "$MACOS_ONLY" != true ] && [ "$WINDOWS_ONLY" != true ]; then
        echo -e "  ${BLUE}Linux targets:${NC}"
        for target in $(get_targets "$LINUX_TARGETS"); do
            deploy_scripts "$target" "linux"
        done
    fi

    if [ -n "${MACOS_TARGETS:-}" ] && [ "$LINUX_ONLY" != true ] && [ "$WINDOWS_ONLY" != true ]; then
        echo -e "  ${BLUE}macOS targets:${NC}"
        for target in $(get_targets "$MACOS_TARGETS"); do
            deploy_scripts "$target" "macos"
        done
    fi

    if [ -n "${WINDOWS_TARGETS:-}" ] && [ "$LINUX_ONLY" != true ] && [ "$MACOS_ONLY" != true ]; then
        echo -e "  ${BLUE}Windows targets:${NC}"
        for target in $(get_targets "$WINDOWS_TARGETS"); do
            deploy_scripts "$target" "windows"
        done
    fi
}

# Phase 2: Discovery & Recon (all platforms)
phase_discovery() {
    phase_header 2 "DISCOVERY & RECONNAISSANCE"

    if [ -n "${LINUX_TARGETS:-}" ] && [ "$MACOS_ONLY" != true ] && [ "$WINDOWS_ONLY" != true ]; then
        for target in $(get_targets "$LINUX_TARGETS"); do
            run_remote "$target" "apt-lateral-movement.sh" \
                "Linux discovery & lateral movement (T1046, T1018, T1007)"
        done
    fi

    if [ -n "${MACOS_TARGETS:-}" ] && [ "$LINUX_ONLY" != true ] && [ "$WINDOWS_ONLY" != true ]; then
        for target in $(get_targets "$MACOS_TARGETS"); do
            run_remote "$target" "apt-lateral-movement.sh" \
                "macOS discovery & lateral movement (T1046, T1018, T1007)"
            run_remote "$target" "macos-attacks.sh" \
                "macOS-specific attacks (T1543, T1059, T1553)"
        done
    fi

    phase_delay
}

# Phase 3: Credential Harvesting (all platforms)
phase_credential_harvest() {
    phase_header 3 "CREDENTIAL HARVESTING"

    if [ -n "${LINUX_TARGETS:-}" ] && [ "$MACOS_ONLY" != true ] && [ "$WINDOWS_ONLY" != true ]; then
        for target in $(get_targets "$LINUX_TARGETS"); do
            run_remote "$target" "apt-credential-harvest.sh" \
                "Linux credential harvest (T1003.008, T1552, T1555)"
        done
    fi

    if [ -n "${MACOS_TARGETS:-}" ] && [ "$LINUX_ONLY" != true ] && [ "$WINDOWS_ONLY" != true ]; then
        for target in $(get_targets "$MACOS_TARGETS"); do
            run_remote "$target" "apt-credential-harvest.sh" \
                "macOS credential harvest (T1555.001, T1552, T1555.003)"
        done
    fi

    if [ -n "${WINDOWS_TARGETS:-}" ] && [ "$LINUX_ONLY" != true ] && [ "$MACOS_ONLY" != true ]; then
        for target in $(get_targets "$WINDOWS_TARGETS"); do
            run_remote_windows "$target" "powershell-attacks.ps1" \
                "Windows PowerShell attacks (T1059.001, T1003)"
        done
    fi

    phase_delay
}

# Phase 4: C2 & Exfiltration (Linux/macOS — bash required)
phase_c2_exfil() {
    phase_header 4 "C2 ESTABLISHMENT & DATA EXFILTRATION"

    if [ -n "${LINUX_TARGETS:-}" ] && [ "$MACOS_ONLY" != true ] && [ "$WINDOWS_ONLY" != true ]; then
        for target in $(get_targets "$LINUX_TARGETS"); do
            run_remote "$target" "apt-c2-exfil.sh" \
                "C2 beaconing + DNS tunneling + data exfil (T1071, T1048)"
        done
    fi

    if [ -n "${MACOS_TARGETS:-}" ] && [ "$LINUX_ONLY" != true ] && [ "$WINDOWS_ONLY" != true ]; then
        for target in $(get_targets "$MACOS_TARGETS"); do
            run_remote "$target" "apt-c2-exfil.sh" \
                "C2 beaconing + DNS tunneling + data exfil (T1071, T1048)"
        done
    fi

    phase_delay
}

# Phase 5: Privilege Escalation (Linux only)
phase_privesc() {
    phase_header 5 "PRIVILEGE ESCALATION"

    if [ -n "${LINUX_TARGETS:-}" ] && [ "$MACOS_ONLY" != true ] && [ "$WINDOWS_ONLY" != true ]; then
        for target in $(get_targets "$LINUX_TARGETS"); do
            run_remote "$target" "privilege-escalation.sh" \
                "Linux privilege escalation (T1548.003)"
        done
    else
        echo -e "  ${YELLOW}Skipped:${NC} No Linux targets for privilege escalation"
    fi

    phase_delay
}

# Phase 6: Collect results and clean up
phase_collect() {
    phase_header 6 "COLLECT RESULTS & CLEANUP"

    local all_targets=""
    [ -n "${LINUX_TARGETS:-}" ] && all_targets="$all_targets $LINUX_TARGETS"
    [ -n "${MACOS_TARGETS:-}" ] && all_targets="$all_targets $MACOS_TARGETS"
    [ -n "${WINDOWS_TARGETS:-}" ] && all_targets="$all_targets $WINDOWS_TARGETS"

    for target in $(echo "$all_targets" | tr ',' ' '); do
        [ -z "$target" ] && continue
        echo -e "  ${BLUE}▸${NC} Collecting logs from ${target}"
        local target_dir="$RESULTS_DIR/${target//[@:.]/_}"
        mkdir -p "$target_dir"
        scp $SSH_OPTS -r "${target}:${REMOTE_WORKDIR}/logs/*" "$target_dir/" 2>/dev/null || \
            echo -e "    ${YELLOW}No logs to collect${NC}"
        cleanup_remote "$target"
    done
}

# =============================================================================
# REPORT
# =============================================================================

generate_report() {
    local report="$RESULTS_DIR/killchain_report.md"
    local total_duration=$1

    local minutes=$((total_duration / 60))
    local seconds=$((total_duration % 60))

    cat > "$report" << EOF
# APT29 Multi-Victim Kill Chain Report

**Date**: $(date '+%Y-%m-%d %H:%M:%S')
**Operator**: $(whoami)@$(hostname)
**Duration**: ${minutes}m ${seconds}s

## Targets

| Platform | Hosts |
|----------|-------|
| Linux | ${LINUX_TARGETS:-none} |
| macOS | ${MACOS_TARGETS:-none} |
| Windows | ${WINDOWS_TARGETS:-none} |

## Phase Results

$(if [ -f "$RESULTS_DIR/phase_results.log" ]; then
    echo "| Status | Duration | Target |"
    echo "|--------|----------|--------|"
    while IFS='|' read -r status dur target; do
        echo "| $status | $dur | $target |"
    done < "$RESULTS_DIR/phase_results.log"
else
    echo "No results recorded."
fi)

## MITRE ATT&CK Coverage

| Tactic | Techniques | Platforms |
|--------|-----------|-----------|
| Discovery | T1046, T1018, T1007, T1082, T1552.005 | Linux, macOS |
| Credential Access | T1003.008, T1555.001, T1552, T1558.003, T1555.003 | Linux, macOS, Windows |
| Persistence | T1543.001, T1543.004, T1547.015 | macOS |
| Execution | T1059.001, T1059.002 | macOS, Windows |
| Defense Evasion | T1070.002, T1070.006, T1553.001 | Linux, macOS |
| Lateral Movement | T1021.004 | Linux, macOS |
| Command & Control | T1071.001, T1071.004 | Linux, macOS |
| Exfiltration | T1074.001, T1048.003, T1573.001, T1567.002 | Linux, macOS |
| Privilege Escalation | T1548.003 | Linux |

## Verification Checklist
- [ ] Check Wazuh alerts across all agents
- [ ] Run anomaly detector — verify beacon + DNS exfil detection
- [ ] Correlate alerts across hosts (same timeframe, different agents)
- [ ] Test incident response playbook activation
- [ ] Review per-host logs in: $RESULTS_DIR/
EOF

    echo -e "${GREEN}✓${NC} Report: $report"
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    parse_args "$@"

    print_header "APT29 Multi-Victim Kill Chain"

    # Check we have at least one target
    if [ -z "${LINUX_TARGETS:-}" ] && [ -z "${MACOS_TARGETS:-}" ] && [ -z "${WINDOWS_TARGETS:-}" ]; then
        echo -e "${RED}ERROR: No targets defined.${NC}"
        echo ""
        echo "Set target environment variables:"
        echo "  export LINUX_TARGETS=\"ubuntu@10.0.2.100,ubuntu@10.0.2.101\""
        echo "  export MACOS_TARGETS=\"admin@10.0.3.50\""
        echo "  export WINDOWS_TARGETS=\"administrator@10.0.4.200\""
        echo ""
        echo "Or use a config file:"
        echo "  $0 --config=targets.conf"
        echo ""
        echo "Run $0 --help for full usage."
        exit 1
    fi

    safety_check "a MULTI-VICTIM APT29 kill chain across all defined targets" "$@"

    # Display target summary
    echo ""
    echo -e "  ${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${RED}  TARGET MATRIX${NC}"
    echo -e "  ${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    if [ -n "${LINUX_TARGETS:-}" ]; then
        echo -e "  🐧 ${BLUE}Linux:${NC}"
        for t in $(get_targets "$LINUX_TARGETS"); do echo "     → $t"; done
    fi
    if [ -n "${MACOS_TARGETS:-}" ]; then
        echo -e "  🍎 ${BLUE}macOS:${NC}"
        for t in $(get_targets "$MACOS_TARGETS"); do echo "     → $t"; done
    fi
    if [ -n "${WINDOWS_TARGETS:-}" ]; then
        echo -e "  🪟 ${BLUE}Windows:${NC}"
        for t in $(get_targets "$WINDOWS_TARGETS"); do echo "     → $t"; done
    fi

    echo ""
    echo -e "  ${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${RED}  KILL CHAIN SEQUENCE${NC}"
    echo -e "  ${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  Phase 1: ${BLUE}Deploy${NC}                → SCP scripts to all targets"
    echo -e "      │"
    echo -e "  Phase 2: ${BLUE}Discovery${NC}             → Recon on all platforms"
    echo -e "      │"
    echo -e "  Phase 3: ${BLUE}Credential Harvest${NC}    → Platform-specific cred theft"
    echo -e "      │"
    echo -e "  Phase 4: ${BLUE}C2 & Exfiltration${NC}     → HTTP beaconing + DNS tunneling"
    echo -e "      │"
    echo -e "  Phase 5: ${BLUE}Privilege Escalation${NC}   → Linux sudo/SUID exploitation"
    echo -e "      │"
    echo -e "  Phase 6: ${BLUE}Collect & Cleanup${NC}     → Gather logs, remove artifacts"
    echo ""

    # Validate connectivity
    echo -e "  ${YELLOW}Validating target connectivity...${NC}"
    if [ -n "${LINUX_TARGETS:-}" ]; then validate_targets "Linux" "$LINUX_TARGETS" || true; fi
    if [ -n "${MACOS_TARGETS:-}" ]; then validate_targets "macOS" "$MACOS_TARGETS" || true; fi
    if [ -n "${WINDOWS_TARGETS:-}" ]; then validate_targets "Windows" "$WINDOWS_TARGETS" || true; fi
    echo ""

    local global_start=$(date +%s)
    log_info "Kill chain started at $(date '+%Y-%m-%d %H:%M:%S')"
    log_info "Results: $RESULTS_DIR"

    # Execute kill chain
    phase_deploy
    phase_discovery
    phase_credential_harvest
    phase_c2_exfil
    phase_privesc
    phase_collect

    local global_end=$(date +%s)
    local total_duration=$((global_end - global_start))

    generate_report "$total_duration"

    echo ""
    print_header "KILL CHAIN COMPLETE"
    echo ""
    local minutes=$((total_duration / 60))
    local seconds=$((total_duration % 60))
    echo -e "  Total duration: ${minutes}m ${seconds}s"
    echo -e "  Targets hit:    $(echo "${LINUX_TARGETS:-},${MACOS_TARGETS:-},${WINDOWS_TARGETS:-}" | tr ',' '\n' | grep -c .)"
    echo -e "  Results:        $RESULTS_DIR/"
    echo ""
    echo "  Verification:"
    echo "    1. Check Wazuh dashboard — correlate alerts across agents"
    echo "    2. Run: cd ai-analyst && python3 src/detect_anomalies.py --demo"
    echo "    3. Review kill chain report: $RESULTS_DIR/killchain_report.md"
    echo ""
}

main "$@"
