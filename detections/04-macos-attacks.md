# macOS Detection Rules

## Overview

This document covers the macOS-specific detection rules for the Cloud SOC Platform. These rules complement the general `local_rules.xml` and are specifically designed to detect attack techniques targeting Apple macOS systems.

## 🍎 MITRE ATT&CK Coverage (macOS)

### Tactics Covered

| Tactic | Techniques | Rules |
|--------|------------|-------|
| **Persistence** | T1543.001, T1543.004, T1547.015, T1053.003 | 200200-200204 |
| **Execution** | T1059.002, T1059.004, T1059.007 | 200210-200213 |
| **Credential Access** | T1555.001, T1555.003, T1552.004, T1539 | 200220-200224 |
| **Defense Evasion** | T1553.001, T1518.001, T1562, T1562.001, T1562.004 | 200230-200234 |
| **Discovery** | T1082, T1016, T1087.002, T1518 | 200240-200243 |
| **Collection** | T1113, T1115, T1083, T1552 | 200250-200252 |
| **Command & Control** | T1572, T1095 | 200260-200262 |
| **Lateral Movement** | T1021.004, T1021.005 | 200270-200272 |

## 📊 Detection Rules Summary

### Total macOS Rules: 28

| Category | Count | Severity Range |
|----------|-------|----------------|
| Persistence | 5 | HIGH (10-12) |
| Execution | 4 | MEDIUM-HIGH (8-12) |
| Credential Access | 5 | HIGH (10-12) |
| Defense Evasion | 5 | MEDIUM-CRITICAL (6-15) |
| Discovery | 4 | MEDIUM (6-8) |
| Collection | 3 | MEDIUM-HIGH (8-10) |
| C2 | 3 | HIGH-CRITICAL (10-15) |
| Lateral Movement | 3 | MEDIUM-HIGH (8-10) |

## 🔍 Rule Details

### 1. Persistence (5 rules)

| Rule ID | Description | Severity | MITRE |
|---------|-------------|----------|-------|
| 200200 | Launch Agent created (user-level) | HIGH | T1543.001 |
| 200201 | Launch Daemon created (system-level) | HIGH | T1543.004 |
| 200202 | Login Items modified | HIGH | T1547.015 |
| 200203 | Cron job created/modified | HIGH | T1053.003 |
| 200204 | Periodic scripts modified | HIGH | T1053.003 |

**Key Paths Monitored:**
- `~/Library/LaunchAgents/`
- `/Library/LaunchAgents/`
- `/Library/LaunchDaemons/`
- `/etc/periodic/`
- `/var/at/tabs/`

### 2. Execution (4 rules)

| Rule ID | Description | Severity | MITRE |
|---------|-------------|----------|-------|
| 200210 | osascript (AppleScript) executed | MEDIUM | T1059.002 |
| 200211 | osascript with JavaScript (JXA) | HIGH | T1059.007 |
| 200212 | osascript executing shell commands | HIGH | T1059.002+004 |
| 200213 | Download and execute pattern | HIGH | T1059.004, T1105 |

**Techniques Detected:**
- AppleScript execution
- JavaScript for Automation (JXA)
- Shell command injection via osascript
- curl/wget piped to shell interpreters

### 3. Credential Access (5 rules)

| Rule ID | Description | Severity | MITRE |
|---------|-------------|----------|-------|
| 200220 | Keychain credential extraction | HIGH | T1555.001 |
| 200221 | Keychain database accessed | HIGH | T1555.001 |
| 200222 | Safari credential files accessed | HIGH | T1555.003 |
| 200223 | Chrome credential/cookie files | HIGH | T1555.003, T1539 |
| 200224 | SSH private key accessed | HIGH | T1552.004 |

**Protected Assets:**
- `~/Library/Keychains/*.keychain-db`
- `~/Library/Safari/Passwords.plist`
- `~/Library/Application Support/Google/Chrome/Default/Login Data`
- `~/.ssh/id_rsa`, `id_ed25519`, `id_ecdsa`

### 4. Defense Evasion (5 rules)

| Rule ID | Description | Severity | MITRE |
|---------|-------------|----------|-------|
| 200230 | Gatekeeper bypass attempt | HIGH | T1553.001 |
| 200231 | SIP status checked | MEDIUM | T1518.001 |
| 200232 | TCC database accessed | CRITICAL | T1562 |
| 200233 | XProtect/MRT modification | HIGH | T1562.001 |
| 200234 | Application Firewall disabled | HIGH | T1562.004 |

**Security Mechanisms Monitored:**
- Gatekeeper (`spctl`, quarantine attributes)
- System Integrity Protection (`csrutil`)
- Transparency, Consent, Control (TCC.db)
- XProtect / Malware Removal Tool
- Application Firewall

### 5. Discovery (4 rules)

| Rule ID | Description | Severity | MITRE |
|---------|-------------|----------|-------|
| 200240 | system_profiler executed | MEDIUM | T1082 |
| 200241 | Network configuration discovery | MEDIUM | T1016 |
| 200242 | Directory Services enumeration | MEDIUM | T1087.002 |
| 200243 | Installed applications enumeration | MEDIUM | T1518 |

### 6. Collection (3 rules)

| Rule ID | Description | Severity | MITRE |
|---------|-------------|----------|-------|
| 200250 | Screen capture utility | MEDIUM | T1113 |
| 200251 | Clipboard access (pbcopy/pbpaste) | MEDIUM | T1115 |
| 200252 | Sensitive file search (find) | HIGH | T1083, T1552 |

### 7. Command & Control (3 rules)

| Rule ID | Description | Severity | MITRE |
|---------|-------------|----------|-------|
| 200260 | SSH tunnel created | HIGH | T1572 |
| 200261 | Network tool (nc/socat) executed | HIGH | T1095 |
| 200262 | Reverse shell detected | CRITICAL | T1059.004 |

### 8. Lateral Movement (3 rules)

| Rule ID | Description | Severity | MITRE |
|---------|-------------|----------|-------|
| 200270 | SSH to multiple hosts | MEDIUM | T1021.004 |
| 200271 | VNC/Screen Sharing initiated | MEDIUM | T1021.005 |
| 200272 | Apple Remote Desktop activity | HIGH | T1021.005 |

## 🚀 Deployment

### Prerequisites

1. **Wazuh Agent on macOS**
   ```bash
   # Install Wazuh agent
   curl -so wazuh-agent.pkg https://packages.wazuh.com/4.x/macos/wazuh-agent-4.x.x.pkg
   sudo installer -pkg wazuh-agent.pkg -target /
   
   # Configure manager IP
   sudo /Library/Ossec/bin/agent-auth -m MANAGER_IP
   
   # Start agent
   sudo /Library/Ossec/bin/wazuh-control start
   ```

2. **Enable Audit Logging**
   ```bash
   # Enable audit daemon
   sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist
   
   # Configure audit policy
   sudo vim /etc/security/audit_control
   # flags:lo,aa,ad,fd,fc,cl
   ```

3. **File Integrity Monitoring**
   ```xml
   <!-- Add to ossec.conf on macOS agent -->
   <syscheck>
     <directories check_all="yes" realtime="yes">~/Library/LaunchAgents</directories>
     <directories check_all="yes" realtime="yes">/Library/LaunchAgents</directories>
     <directories check_all="yes" realtime="yes">/Library/LaunchDaemons</directories>
     <directories check_all="yes">~/.ssh</directories>
   </syscheck>
   ```

### Deploy Rules

```bash
# Copy to Wazuh server
scp macos_rules.xml wazuh-server:/var/ossec/etc/rules/

# Verify syntax
/var/ossec/bin/wazuh-logtest

# Restart manager
systemctl restart wazuh-manager
```

## 🧪 Testing

Run the macOS attack simulation:

```bash
cd attack-simulation
./macos-attacks.sh
```

### Expected Alerts by Test

| Test | Rule ID | Alert Description |
|------|---------|-------------------|
| Launch Agent creation | 200200 | macOS Launch Agent created |
| osascript execution | 200210 | osascript executed |
| osascript + shell | 200212 | osascript shell execution |
| Keychain access | 200220/221 | Keychain access detected |
| Gatekeeper check | 200230 | Gatekeeper check |
| SIP check | 200231 | SIP status checked |
| Screen capture | 200250 | Screen capture utility |
| Clipboard | 200251 | Clipboard access detected |

## 📈 Tuning Recommendations

### High False Positive Risk

| Rule ID | Condition | Whitelist Strategy |
|---------|-----------|-------------------|
| 200210 | osascript | Whitelist known automation scripts |
| 200240 | system_profiler | Whitelist IT management tools |
| 200241 | networksetup | Whitelist MDM operations |
| 200251 | pbcopy/pbpaste | Consider disabling in dev environments |

### Low False Positive Risk

| Rule ID | Notes |
|---------|-------|
| 200201 | Launch Daemons rarely created normally |
| 200232 | TCC database access is highly suspicious |
| 200220 | Keychain dumping is rarely legitimate |
| 200262 | Reverse shells are never legitimate |

## 🔗 Related Resources

- [macOS Security Overview (Apple)](https://support.apple.com/guide/security/)
- [MITRE ATT&CK macOS Matrix](https://attack.mitre.org/matrices/enterprise/macos/)
- [Objective-See Tools](https://objective-see.org/tools.html)
- [Wazuh macOS Documentation](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/macos.html)

---

**Last Updated**: 2026-01-28  
**Version**: 1.0  
**Total Rules**: 28
