# Privilege Escalation Detection

## Overview
Detects privilege escalation attempts on Linux and Windows systems, focusing on sudo abuse, unauthorized privilege elevation, and suspicious administrative actions.

## MITRE ATT&CK Mapping
- **Primary Technique**: T1548.003 - Abuse Elevation Control Mechanism: Sudo and Sudo Caching
- **Related Techniques**:
  - T1078.003 - Valid Accounts: Local Accounts
  - T1059 - Command and Scripting Interpreter
- **Tactic**: Privilege Escalation, Defense Evasion

## Detection Rules

### Rule 200020: Sudo Command Executed (Baseline)
```xml
<rule id="200020" level="3">
  <if_sid>5401</if_sid>
  <description>Sudo command executed</description>
</rule>
```

**Purpose**: Informational baseline for sudo usage tracking

**Severity**: Low (3) - Normal administrative activity

### Rule 200021: Suspicious Sudo Commands
```xml
<rule id="200021" level="10">
  <if_sid>200020</if_sid>
  <field name="command" type="pcre2">(?i)su\s+-|/bin/bash|/bin/sh|nc\s+|python|perl|ruby|php</field>
  <description>Suspicious sudo command executed (shell/scripting interpreter)</description>
</rule>
```

**Detects:**
- `sudo su -` (switch to root)
- `sudo /bin/bash` (spawn root shell)
- `sudo nc` (netcat for reverse shells)
- `sudo python/perl/ruby/php` (scripting interpreters with root)

**Why it matters**: These commands can be used to gain persistent root access or execute malicious code with elevated privileges.

**Severity**: High (10)

### Rule 200022: Direct Root Shell Escalation
```xml
<rule id="200022" level="12">
  <if_sid>200020</if_sid>
  <field name="command" type="pcre2">sudo\s+su\s*$|sudo\s+-i|sudo\s+bash</field>
  <description>Sudo escalation to root shell detected</description>
</rule>
```

**Detects:**
- `sudo su` (become root)
- `sudo -i` (interactive root shell)
- `sudo bash` (root bash shell)

**Why it matters**: Direct escalation to root shell, bypassing normal privilege controls.

**Severity**: High (12)

### Rule 200032: User Added to Privileged Group (Linux)
```xml
<rule id="200032" level="12">
  <decoded_as>auditd</decoded_as>
  <field name="auditd.key">identity</field>
  <field name="auditd.file" type="pcre2">/etc/group|/etc/sudoers</field>
  <description>User added to privileged group (sudo/wheel/admin)</description>
</rule>
```

**Detects:**
- Modifications to `/etc/group` (adding users to sudo/wheel)
- Modifications to `/etc/sudoers` (granting sudo permissions)

**Why it matters**: Attackers add backdoor accounts to privileged groups for persistence.

**Severity**: High (12)

### Rule 200033: User Added to Administrators (Windows)
```xml
<rule id="200033" level="12">
  <if_sid>60000</if_sid>
  <field name="win.system.eventID">4732</field>
  <field name="win.eventdata.targetUserName" type="pcre2">(?i)administrators|domain admins</field>
  <description>User added to Windows Administrators group</description>
</rule>
```

**Detects:**
- Windows Event ID 4732: Member added to security-enabled local group
- Specifically monitors Administrators and Domain Admins groups

**Why it matters**: Unauthorized admin group membership = full system compromise.

**Severity**: High (12)

## Data Sources

### Linux
- **Logs**: `/var/log/auth.log`, `/var/log/secure`
- **Auditd**: Monitors file changes to `/etc/group`, `/etc/sudoers`
- **Wazuh SID 5401**: Sudo command execution

### Windows
- **Event ID 4732**: Member added to security-enabled local group
- **Event ID 4728**: Member added to security-enabled global group
- **Event ID 4756**: Member added to security-enabled universal group

### Prerequisites

#### Linux: Enable Auditd Rules
```bash
# Add to /etc/audit/rules.d/audit.rules
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/sudoers -p wa -k identity
-w /etc/sudoers.d/ -p wa -k identity

# Reload auditd
sudo augenrules --load
sudo systemctl restart auditd
```

#### Windows: Enable Advanced Audit Policy
```powershell
# Enable security group management auditing
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
```

## Testing Procedures

### Test 1: Suspicious Sudo Command (Rule 200021)
```bash
# On Linux endpoint
# Test 1: Sudo with bash
sudo bash -c "echo 'Test alert'"

# Test 2: Sudo with python
sudo python3 -c "print('Test alert')"

# Test 3: Sudo with netcat (if installed)
sudo nc -h

# Expected: Rule 200021 alert for each command
```

### Test 2: Root Shell Escalation (Rule 200022)
```bash
# Test direct root shell
sudo su
# Type 'exit' immediately

# Test interactive root
sudo -i
# Type 'exit' immediately

# Expected: Rule 200022 alert
```

### Test 3: Add User to Sudo Group (Rule 200032)
```bash
# Create test user
sudo useradd testuser

# Add to sudo group (THIS WILL TRIGGER ALERT)
sudo usermod -aG sudo testuser

# Verify alert triggered
# Clean up
sudo userdel testuser

# Expected: Rule 200032 alert
```

### Test 4: Windows Admin Group Addition (Rule 200033)
```powershell
# On Windows endpoint (requires admin privileges)
# Create test user
net user testuser TestPass123! /add

# Add to Administrators group (THIS WILL TRIGGER ALERT)
net localgroup Administrators testuser /add

# Clean up
net localgroup Administrators testuser /delete
net user testuser /delete

# Expected: Rule 200033 alert
```

### Verification
```bash
# On Wazuh server
tail -f /var/ossec/logs/alerts/alerts.log | grep "10002[0-3]\|10003[2-3]"

# Query specific rule
/var/ossec/bin/wazuh-logtest
# Paste sample log entry to test rule matching
```

## False Positive Scenarios

### Common False Positives

#### 1. Legitimate System Administration
**Scenario**: System admin performs routine maintenance
```bash
# Normal admin activity
sudo apt update
sudo systemctl restart nginx
sudo vim /etc/hosts
```

**Tuning**: These are normal and won't trigger (not in regex pattern)

#### 2. Automated Configuration Management
**Scenario**: Ansible/Puppet/Chef uses sudo for automation
```bash
# Ansible playbook execution
sudo bash -c "some_command"  # WILL trigger 200021
```

**Tuning**: Whitelist automation user accounts
```xml
<rule id="200021" level="10">
  <if_sid>200020</if_sid>
  <field name="command" type="pcre2">(?i)su\s+-|/bin/bash|/bin/sh</field>
  <field name="user" negate="yes">ansible</field>
  <description>Suspicious sudo command executed</description>
</rule>
```

#### 3. Onboarding New Admins
**Scenario**: IT adds new administrator to sudo group
```bash
# Legitimate admin addition
sudo usermod -aG sudo newadmin
```

**Tuning**: 
- Correlate with change management tickets
- Whitelist during maintenance windows
- Require approval workflow for group changes

#### 4. Development Environments
**Scenario**: Developers use sudo for local testing

**Tuning**: Lower severity for dev systems
```xml
<!-- Lower severity for dev environments -->
<rule id="200021" level="5">
  <if_sid>200020</if_sid>
  <field name="command" type="pcre2">(?i)su\s+-|/bin/bash</field>
  <field name="hostname" type="pcre2">dev-|test-|staging-</field>
  <description>Suspicious sudo command on dev system (informational)</description>
</rule>
```

## Response Playbook

### Tier 1 Analyst Actions

#### For Rules 200021-200022 (Suspicious Sudo)
1. **Immediate verification**
   - Who executed the command? (Check user field)
   - What was the exact command? (Review full log)
   - When did it occur? (Business hours vs off-hours)
   - Where? (Which system/hostname)

2. **Context gathering**
   ```bash
   # On Linux system
   # Check recent sudo history
   sudo grep "sudo" /var/log/auth.log | tail -20
   
   # Check who is currently logged in
   who
   w
   
   # Check recent logins
   last | head -20
   ```

3. **Risk assessment**
   - **HIGH RISK**: Off-hours, unknown user, production system
   - **MEDIUM RISK**: Business hours, known user, unusual command
   - **LOW RISK**: Known admin, expected activity

4. **Initial response**
   - If HIGH RISK: Escalate to Tier 2 immediately
   - If MEDIUM RISK: Contact user to verify activity
   - If LOW RISK: Document and monitor

#### For Rules 200032-200033 (Group Modification)
1. **IMMEDIATE ESCALATION** - This is high-priority
2. **Verify change management**
   - Is there an approved ticket for this change?
   - Was it scheduled maintenance?
   
3. **If unauthorized**
   - Escalate to Tier 2
   - Do NOT remove user yet (preserve evidence)
   - Isolate affected system if possible

### Tier 2 Analyst Actions

#### Investigation
```bash
# Linux: Full sudo audit
sudo grep "sudo" /var/log/auth.log* | grep "USERNAME"

# Check for privilege escalation exploits
sudo grep -i "exploit\|CVE\|privilege" /var/log/syslog

# Review auditd logs
sudo ausearch -k identity -ts recent

# Check for unauthorized sudoers entries
sudo cat /etc/sudoers
sudo ls -la /etc/sudoers.d/

# Windows: Review security logs
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4732,4728,4756} -MaxEvents 100
```

#### Containment
```bash
# If unauthorized privilege escalation detected:

# 1. Remove unauthorized sudo access
sudo deluser MALICIOUS_USER sudo
sudo deluser MALICIOUS_USER wheel

# 2. Lock the account
sudo usermod -L MALICIOUS_USER

# 3. Kill all user sessions
sudo pkill -u MALICIOUS_USER

# 4. Review and remove any backdoors
sudo crontab -u MALICIOUS_USER -l
sudo ls -la /home/MALICIOUS_USER/.ssh/

# 5. Force password reset for all admin accounts
sudo passwd ADMIN_USER
```

#### Eradication
1. Remove unauthorized accounts
2. Review and restore `/etc/sudoers` from backup
3. Audit all privileged accounts
4. Reset all admin passwords
5. Review SSH keys for all admin accounts

#### Recovery
1. Restore system to known-good state
2. Re-enable legitimate admin access
3. Update detection rules based on TTPs observed
4. Implement additional controls (MFA, PAM, etc.)

## Advanced Detection

### Correlation Rule: Rapid Privilege Escalation
```xml
<!-- Alert if user goes from normal user to sudo in < 5 minutes -->
<rule id="200025" level="15" frequency="2" timeframe="300">
  <if_matched_group>privilege_escalation</if_matched_group>
  <same_user />
  <description>Rapid privilege escalation detected (CRITICAL)</description>
  <mitre>
    <id>T1548.003</id>
  </mitre>
</rule>
```

### Behavioral Analytics
Monitor for:
- First-time sudo usage by a user
- Sudo usage outside normal working hours
- Sudo from unusual source IPs (for SSH sessions)
- Multiple failed sudo attempts followed by success

## Metrics & KPIs
- **MTTD**: < 1 minute (real-time detection)
- **MTTR**: < 15 minutes for investigation
- **False Positive Rate**: Target < 15% (admin activity is common)
- **Coverage**: All Linux/Windows systems with admin accounts

## Compliance Mapping
- **PCI DSS**: 10.2.2, 10.2.5 (Privileged user actions)
- **NIST 800-53**: AU.14, AC.6 (Least privilege, audit privileged functions)
- **GDPR**: Article 32 (Security of processing)
- **HIPAA**: 164.312(a)(2)(i) (Access control)
- **SOC 2**: CC6.8 (Restricts access to privileged functions)

## Preventive Controls

### Linux
1. **Restrict sudo access**: Only grant to necessary users
2. **Use sudo logging**: Enable detailed sudo logging
3. **Implement MFA**: Require 2FA for sudo
4. **Use sudo timeout**: Reduce sudo credential caching
5. **Audit sudoers regularly**: Review `/etc/sudoers` monthly

```bash
# Sudo configuration best practices
# In /etc/sudoers:
Defaults    timestamp_timeout=5    # Reduce cache to 5 minutes
Defaults    log_output             # Log all sudo commands
Defaults    requiretty             # Require TTY for sudo
```

### Windows
1. **Minimize admin accounts**: Follow least privilege
2. **Use LAPS**: Local Administrator Password Solution
3. **Enable Protected Users group**: For high-value accounts
4. **Implement JIT access**: Just-in-time admin access
5. **Use PAM**: Privileged Access Management solution

## References
- [MITRE ATT&CK T1548.003](https://attack.mitre.org/techniques/T1548/003/)
- [Linux Sudo Security Best Practices](https://www.sudo.ws/security.html)
- [Microsoft Privileged Access Strategy](https://docs.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-strategy)
- [NIST SP 800-53 AC-6: Least Privilege](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf)

## Version History
- **v1.0** (2026-01-28): Initial detection rules
- **Coverage**: Linux (Ubuntu/RHEL/CentOS) and Windows Server
- **Status**: Production-ready
