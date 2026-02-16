# Incident Response Playbook: macOS Compromise

## 📋 Playbook Information

| Field | Value |
|-------|-------|
| **Playbook ID** | IR-PB-006 |
| **Version** | 1.0 |
| **Last Updated** | 2026-01-28 |
| **MITRE ATT&CK** | Multiple macOS-specific techniques |
| **Severity** | MEDIUM-CRITICAL (P3-P1) |
| **MTTR Target** | 45 minutes |

## 🍎 Incident Overview

### Description
This playbook covers incident response procedures specific to macOS systems. macOS has unique security mechanisms (SIP, TCC, Gatekeeper, Keychain) that require specialized investigation and remediation techniques.

### Detection Rules
- **Rule 200200-200204**: Persistence (Launch Agents/Daemons)
- **Rule 200210-200213**: Execution (osascript, JXA)
- **Rule 200220-200224**: Credential Access (Keychain, SSH keys)
- **Rule 200230-200234**: Defense Evasion (Gatekeeper, SIP, TCC)
- **Rule 200240-200243**: Discovery
- **Rule 200250-200262**: Collection, C2, Lateral Movement

### macOS Security Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     macOS SECURITY LAYERS                    │
├─────────────────────────────────────────────────────────────┤
│  Gatekeeper    │  Code signing enforcement                  │
│  XProtect      │  Built-in malware detection                │
│  MRT           │  Malware Removal Tool                      │
│  SIP           │  System Integrity Protection               │
│  TCC           │  Transparency, Consent, Control            │
│  Keychain      │  Credential storage                        │
│  Secure Enclave│  Hardware security (T2/Apple Silicon)      │
└─────────────────────────────────────────────────────────────┘
```

---

## ⚡ PHASE 1: TRIAGE (5 minutes)

### Initial Assessment

```bash
# Quick system status check
echo "=== macOS Security Status ==="
echo "Hostname: $(hostname)"
echo "macOS Version: $(sw_vers -productVersion)"
echo "Serial: $(system_profiler SPHardwareDataType | grep Serial)"
echo "Logged in user: $(whoami)"
echo "SIP Status: $(csrutil status)"
echo "Gatekeeper: $(spctl --status)"
```

### Severity Determination

| Indicator | Severity | Action |
|-----------|----------|--------|
| TCC database accessed | **P1 CRITICAL** | Immediate isolation |
| Keychain dumped | **P1 CRITICAL** | Credential rotation |
| Launch Daemon in /System | **P1 CRITICAL** | Potential rootkit |
| SIP disabled | **P1 CRITICAL** | Full forensic analysis |
| Unknown Launch Agent | **P2 HIGH** | Urgent investigation |
| osascript with shellcode | **P2 HIGH** | Malware investigation |
| Gatekeeper bypass | **P2 HIGH** | Verify binary origin |
| Screen capture detected | **P3 MEDIUM** | Confirm legitimacy |

### Quick Questions

1. ☐ What triggered the alert?
2. ☐ Is the affected user an admin?
3. ☐ Has the system left corporate network recently?
4. ☐ Any recent software installations?
5. ☐ Any phishing emails received?
6. ☐ Is FileVault enabled?

---

## 🔍 PHASE 2: INVESTIGATION

### Create Evidence Directory

```bash
# Create timestamped evidence directory
INCIDENT_ID="INC-$(date +%Y%m%d-%H%M%S)"
EVIDENCE_DIR="/tmp/evidence/$INCIDENT_ID"
mkdir -p "$EVIDENCE_DIR"
cd "$EVIDENCE_DIR"

echo "Evidence directory: $EVIDENCE_DIR"
```

### System Information

```bash
# Comprehensive system info
system_profiler SPSoftwareDataType SPHardwareDataType > "$EVIDENCE_DIR/system_info.txt"

# macOS version and build
sw_vers >> "$EVIDENCE_DIR/system_info.txt"

# Uptime and last reboot
uptime >> "$EVIDENCE_DIR/system_info.txt"
last reboot | head -5 >> "$EVIDENCE_DIR/system_info.txt"
```

### Persistence Mechanisms

```bash
# ========== LAUNCH AGENTS/DAEMONS ==========
echo "=== Launch Agents (User) ===" > "$EVIDENCE_DIR/persistence.txt"
ls -la ~/Library/LaunchAgents/ >> "$EVIDENCE_DIR/persistence.txt" 2>/dev/null

echo -e "\n=== Launch Agents (Global) ===" >> "$EVIDENCE_DIR/persistence.txt"
ls -la /Library/LaunchAgents/ >> "$EVIDENCE_DIR/persistence.txt" 2>/dev/null

echo -e "\n=== Launch Daemons ===" >> "$EVIDENCE_DIR/persistence.txt"
ls -la /Library/LaunchDaemons/ >> "$EVIDENCE_DIR/persistence.txt" 2>/dev/null

echo -e "\n=== System Launch Daemons ===" >> "$EVIDENCE_DIR/persistence.txt"
ls -la /System/Library/LaunchDaemons/ | grep -v "^total" | head -20 >> "$EVIDENCE_DIR/persistence.txt"

# Check for suspicious plist contents
for plist in ~/Library/LaunchAgents/*.plist /Library/LaunchAgents/*.plist /Library/LaunchDaemons/*.plist; do
    if [ -f "$plist" ]; then
        echo -e "\n=== $plist ===" >> "$EVIDENCE_DIR/plist_contents.txt"
        plutil -p "$plist" >> "$EVIDENCE_DIR/plist_contents.txt" 2>/dev/null
    fi
done

# ========== LOGIN ITEMS ==========
echo -e "\n=== Login Items ===" >> "$EVIDENCE_DIR/persistence.txt"
osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null >> "$EVIDENCE_DIR/persistence.txt"

# ========== CRON JOBS ==========
echo -e "\n=== Cron Jobs ===" >> "$EVIDENCE_DIR/persistence.txt"
crontab -l 2>/dev/null >> "$EVIDENCE_DIR/persistence.txt"
cat /etc/crontab 2>/dev/null >> "$EVIDENCE_DIR/persistence.txt"

# ========== PERIODIC SCRIPTS ==========
echo -e "\n=== Periodic Scripts ===" >> "$EVIDENCE_DIR/persistence.txt"
ls -la /etc/periodic/*/ >> "$EVIDENCE_DIR/persistence.txt" 2>/dev/null
```

### Running Processes

```bash
# All running processes with details
ps auxww > "$EVIDENCE_DIR/processes.txt"

# Process tree
pstree 2>/dev/null > "$EVIDENCE_DIR/pstree.txt" || ps -ejH > "$EVIDENCE_DIR/pstree.txt"

# Processes with network connections
lsof -i -P > "$EVIDENCE_DIR/network_processes.txt"

# Unsigned or suspicious processes
echo "=== Potentially Unsigned Processes ===" > "$EVIDENCE_DIR/unsigned_processes.txt"
for pid in $(ps -eo pid | tail -n +2); do
    path=$(ps -o comm= -p $pid 2>/dev/null)
    if [ -n "$path" ] && [ -f "$path" ]; then
        codesign -v "$path" 2>&1 | grep -v "valid on disk" >> "$EVIDENCE_DIR/unsigned_processes.txt"
    fi
done
```

### Network Connections

```bash
# Active connections
netstat -an > "$EVIDENCE_DIR/netstat.txt"

# DNS cache
dscacheutil -flushcache 2>&1 | head -1 > "$EVIDENCE_DIR/dns.txt"
scutil --dns >> "$EVIDENCE_DIR/dns.txt"

# Network configuration
networksetup -listallhardwareports > "$EVIDENCE_DIR/network_config.txt"
ifconfig -a >> "$EVIDENCE_DIR/network_config.txt"

# ARP cache
arp -a > "$EVIDENCE_DIR/arp.txt"

# Listening ports
lsof -i -P | grep LISTEN > "$EVIDENCE_DIR/listening_ports.txt"
```

### User Activity

```bash
# Current logged in users
who > "$EVIDENCE_DIR/logged_in_users.txt"
last | head -50 >> "$EVIDENCE_DIR/logged_in_users.txt"

# Recent file access
find ~ -type f -mtime -1 2>/dev/null | head -100 > "$EVIDENCE_DIR/recent_files.txt"

# Downloads folder
ls -lahR ~/Downloads/ > "$EVIDENCE_DIR/downloads.txt" 2>/dev/null

# Browser history (Safari)
if [ -f ~/Library/Safari/History.db ]; then
    sqlite3 ~/Library/Safari/History.db "SELECT datetime(visit_time + 978307200, 'unixepoch', 'localtime'), url FROM history_visits INNER JOIN history_items ON history_visits.history_item = history_items.id ORDER BY visit_time DESC LIMIT 100;" > "$EVIDENCE_DIR/safari_history.txt" 2>/dev/null
fi

# Recent shell history
cat ~/.bash_history ~/.zsh_history 2>/dev/null | tail -200 > "$EVIDENCE_DIR/shell_history.txt"
```

### Security Status

```bash
# Security settings
echo "=== Security Status ===" > "$EVIDENCE_DIR/security_status.txt"

echo -e "\n=== SIP Status ===" >> "$EVIDENCE_DIR/security_status.txt"
csrutil status >> "$EVIDENCE_DIR/security_status.txt"

echo -e "\n=== Gatekeeper Status ===" >> "$EVIDENCE_DIR/security_status.txt"
spctl --status >> "$EVIDENCE_DIR/security_status.txt"

echo -e "\n=== FileVault Status ===" >> "$EVIDENCE_DIR/security_status.txt"
fdesetup status >> "$EVIDENCE_DIR/security_status.txt" 2>/dev/null

echo -e "\n=== Firewall Status ===" >> "$EVIDENCE_DIR/security_status.txt"
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate >> "$EVIDENCE_DIR/security_status.txt"

echo -e "\n=== XProtect Version ===" >> "$EVIDENCE_DIR/security_status.txt"
system_profiler SPInstallHistoryDataType | grep -A 5 "XProtect" | head -10 >> "$EVIDENCE_DIR/security_status.txt"
```

### Keychain Analysis

```bash
# List keychains (does not dump passwords)
security list-keychains > "$EVIDENCE_DIR/keychains.txt"

# Keychain metadata
ls -la ~/Library/Keychains/ >> "$EVIDENCE_DIR/keychains.txt"
ls -la /Library/Keychains/ >> "$EVIDENCE_DIR/keychains.txt" 2>/dev/null
```

### TCC Database Check

```bash
# TCC permissions granted
echo "=== TCC Permissions ===" > "$EVIDENCE_DIR/tcc.txt"
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db "SELECT client, service, auth_value, auth_reason FROM access;" 2>/dev/null >> "$EVIDENCE_DIR/tcc.txt"
```

### Unified Logs

```bash
# Recent security-related logs
log show --predicate 'subsystem == "com.apple.securityd"' --last 1h > "$EVIDENCE_DIR/security_logs.txt" 2>/dev/null

# Process execution logs
log show --predicate 'eventMessage contains "exec"' --last 30m > "$EVIDENCE_DIR/exec_logs.txt" 2>/dev/null

# SSH logs
log show --predicate 'process == "sshd"' --last 2h > "$EVIDENCE_DIR/ssh_logs.txt" 2>/dev/null

# Authentication events
log show --predicate 'category == "authorization"' --last 2h > "$EVIDENCE_DIR/auth_logs.txt" 2>/dev/null
```

---

## 🛡️ PHASE 3: CONTAINMENT

### Network Isolation

```bash
# Disable Wi-Fi
networksetup -setairportpower en0 off

# Or disable all networking (extreme)
# sudo ifconfig en0 down
# sudo ifconfig en1 down

# Block specific IP at firewall
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /usr/bin/nc
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --blockapp /usr/bin/nc
```

### Stop Malicious Processes

```bash
# Identify and kill suspicious process
MALICIOUS_PID="<PID>"
kill -9 $MALICIOUS_PID

# Kill by name
pkill -9 -f "suspicious_process_name"
```

### Disable Persistence

```bash
# Unload malicious LaunchAgent
launchctl unload ~/Library/LaunchAgents/com.malicious.plist
launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.malicious.plist

# Remove from loading
launchctl disable user/$(id -u)/com.malicious

# Remove the plist file (after backup)
cp ~/Library/LaunchAgents/com.malicious.plist "$EVIDENCE_DIR/"
rm ~/Library/LaunchAgents/com.malicious.plist

# For system daemons (requires sudo)
sudo launchctl unload /Library/LaunchDaemons/com.malicious.plist
sudo launchctl bootout system /Library/LaunchDaemons/com.malicious.plist
```

### Account Lockdown

```bash
# Change user password
passwd

# Lock screen immediately
pmset displaysleepnow

# If admin compromised, disable the account
# sudo dseditgroup -o edit -d compromised_user -t user admin
```

### Quarantine Malware

```bash
# Create quarantine directory
QUARANTINE_DIR="$EVIDENCE_DIR/quarantine"
mkdir -p "$QUARANTINE_DIR"

# Move suspicious files (preserve metadata)
sudo ditto --rsrc "/path/to/malicious/file" "$QUARANTINE_DIR/"

# Remove execution permissions
chmod -x "$QUARANTINE_DIR/*"

# Add quarantine attribute
xattr -w com.apple.quarantine "0181;$(date +%s);Incident Response;1234" "$QUARANTINE_DIR/*"
```

---

## 🧹 PHASE 4: ERADICATION

### Remove Persistence Mechanisms

```bash
# Remove all suspicious Launch Agents
for plist in ~/Library/LaunchAgents/com.suspicious*.plist; do
    launchctl unload "$plist" 2>/dev/null
    rm -f "$plist"
done

# Remove Login Items
osascript -e 'tell application "System Events" to delete login item "Suspicious Item"'

# Remove cron jobs
crontab -r  # Removes all cron jobs for current user

# Check and clean periodic scripts
sudo rm -f /etc/periodic/daily/malicious_script
```

### Remove Malicious Files

```bash
# Common malware locations
LOCATIONS=(
    "~/Downloads"
    "~/Library/Caches"
    "/tmp"
    "/var/folders"
    "~/.cache"
)

# Search and remove (after verification)
for loc in "${LOCATIONS[@]}"; do
    find "$loc" -name "*.app" -mtime -1 -exec rm -rf {} \; 2>/dev/null
done

# Remove browser extensions
rm -rf ~/Library/Application\ Support/Google/Chrome/Default/Extensions/malicious_extension_id
```

### Verify Code Signatures

```bash
# Check all running applications
for app in /Applications/*.app; do
    codesign -vv "$app" 2>&1 || echo "UNSIGNED: $app"
done
```

### Clear Browser Data

```bash
# Safari
rm -rf ~/Library/Safari/LocalStorage/*
rm -rf ~/Library/Caches/com.apple.Safari/*

# Chrome
rm -rf ~/Library/Application\ Support/Google/Chrome/Default/Cookies
rm -rf ~/Library/Application\ Support/Google/Chrome/Default/Cache/*
```

---

## 🔄 PHASE 5: RECOVERY

### Verify System Integrity

```bash
# Check SIP status
csrutil status

# Check for system file modifications
sudo diskutil verifyVolume /

# Check XProtect
system_profiler SPInstallHistoryDataType | grep -A 5 "XProtect"

# Verify Gatekeeper
spctl --status
```

### Restore Normal Security

```bash
# Re-enable firewall
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on

# Re-enable Gatekeeper
sudo spctl --master-enable

# Clear quarantine from legitimate apps if needed
xattr -d com.apple.quarantine /Applications/LegitimateApp.app
```

### Credential Rotation

```bash
# Force Keychain password change
security delete-keychain login.keychain-db
# User will be prompted to recreate on next login

# Generate new SSH keys
ssh-keygen -t ed25519 -C "new_key_$(date +%Y%m%d)" -f ~/.ssh/id_ed25519_new
rm ~/.ssh/id_rsa  # Remove old keys

# Rotate API keys, tokens, etc.
# Document all credentials that need rotation
```

### Re-enable Network

```bash
# Re-enable Wi-Fi
networksetup -setairportpower en0 on

# Verify network is working
ping -c 3 8.8.8.8
```

### Update macOS

```bash
# Check for updates
softwareupdate -l

# Install all updates
sudo softwareupdate -i -a -R
```

---

## 📊 PHASE 6: POST-INCIDENT

### Documentation

| Section | Content |
|---------|---------|
| Executive Summary | Brief overview for leadership |
| Timeline | Chronological incident events |
| Technical Analysis | Detailed malware/attack analysis |
| Impact Assessment | Data/systems affected |
| Remediation Steps | Actions taken |
| Lessons Learned | Improvements identified |

### macOS-Specific Recommendations

1. **Enable Security Controls**
   - Ensure SIP is enabled
   - Enable FileVault
   - Enable Application Firewall
   - Configure Gatekeeper properly

2. **MDM Enrollment**
   - Enroll in corporate MDM
   - Deploy security profiles
   - Enable remote wipe capability

3. **Monitoring**
   - Deploy Wazuh agent
   - Enable audit logging
   - Configure unified log forwarding

4. **User Training**
   - macOS phishing awareness
   - Safe app installation practices
   - Recognizing social engineering

### Enable Enhanced Logging

```bash
# Enable audit logging
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist

# Configure audit policy
sudo vim /etc/security/audit_control
# Add: flags:lo,aa,ad,fd,fc,cl

# Enable process accounting
sudo accton /var/account/acct
```

---

## 📚 Quick Reference

### Key Locations

| Type | Path |
|------|------|
| Launch Agents (User) | `~/Library/LaunchAgents/` |
| Launch Agents (Global) | `/Library/LaunchAgents/` |
| Launch Daemons | `/Library/LaunchDaemons/` |
| Login Items | `~/Library/Application Support/com.apple.backgroundtaskmanagementagent/` |
| Keychain | `~/Library/Keychains/` |
| TCC Database | `~/Library/Application Support/com.apple.TCC/TCC.db` |
| Unified Logs | `/var/log/` |
| Safari Data | `~/Library/Safari/` |
| Chrome Data | `~/Library/Application Support/Google/Chrome/` |

### Useful Commands

```bash
# Security status
csrutil status          # SIP
spctl --status          # Gatekeeper
fdesetup status         # FileVault

# Process investigation
ps auxww | grep -i suspicious
lsof -c processname

# Persistence
launchctl list | grep -v com.apple
crontab -l

# Network
lsof -i -P
netstat -an | grep LISTEN

# Logs
log show --predicate 'process == "sshd"' --last 1h
log show --style syslog --last 30m
```

---

**Version**: 1.0  
**Last Updated**: 2026-01-28  
**Next Review**: 2026-02-28
