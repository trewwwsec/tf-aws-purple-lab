# Incident Response Playbook: Credential Dumping

## 📋 Playbook Information

| Field | Value |
|-------|-------|
| **Playbook ID** | IR-PB-002 |
| **Version** | 1.0 |
| **Last Updated** | 2026-01-28 |
| **MITRE ATT&CK** | T1003 - OS Credential Dumping |
| **Severity** | CRITICAL (P1) |
| **MTTR Target** | 15 minutes |

## 🚨 Incident Overview

### Description
Credential dumping is the process of obtaining account login and password information from the operating system and software. Attackers use this technique to steal credentials for lateral movement, privilege escalation, and persistence.

### Detection Rules
- **Rule 200013**: Mimikatz detected (CRITICAL)
- **Rule 200070**: Shadow password file accessed (CRITICAL)
- **Rule 200071**: LSASS process accessed (CRITICAL)
- **Rule 200072**: SAM/SECURITY registry hive accessed (CRITICAL)

### Indicators of Compromise (IOCs)
- Mimikatz execution or keywords in logs
- Unauthorized access to `/etc/shadow` (Linux)
- LSASS memory dump (Windows)
- SAM/SECURITY registry hive access (Windows)
- Suspicious use of credential dumping tools
- Unusual process accessing sensitive credential stores

---

## ⚡ PHASE 1: IMMEDIATE ACTIONS (2 minutes)

### ⚠️ CRITICAL - DO THIS FIRST

**This is a P1 incident. Take immediate action:**

1. **ISOLATE THE SYSTEM IMMEDIATELY**
   ```bash
   # On affected system - Cut network access NOW
   sudo iptables -P INPUT DROP
   sudo iptables -P OUTPUT DROP
   sudo iptables -P FORWARD DROP
   
   # Or disable network interface
   sudo ip link set eth0 down
   ```

2. **ALERT INCIDENT COMMANDER**
   - Call (don't email) Incident Commander immediately
   - Brief: "P1 - Credential dumping detected on [SYSTEM]"
   - Provide: System name, detection time, rule ID

3. **PRESERVE EVIDENCE**
   ```bash
   # Capture memory dump (if tools available)
   sudo dd if=/dev/mem of=/tmp/memory-dump-$(date +%Y%m%d-%H%M%S).img
   
   # Capture running processes
   ps auxf > /tmp/processes-$(date +%Y%m%d-%H%M%S).txt
   ```

### Triage Questions

**Answer immediately:**
1. ☐ What tool was used? (Mimikatz, procdump, etc.)
2. ☐ Is this a Windows or Linux system?
3. ☐ What user account executed the tool?
4. ☐ Is the attacker still active on the system?
5. ☐ What credentials could have been accessed?
6. ☐ Are there signs of lateral movement?

---

## 🔍 PHASE 2: INVESTIGATION (10 minutes)

### Evidence Collection

#### Windows System
```powershell
# Create incident directory
$INCIDENT_ID = "INC-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
New-Item -Path "C:\Evidence\$INCIDENT_ID" -ItemType Directory

# Collect PowerShell logs
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    ID=4104
    StartTime=(Get-Date).AddHours(-2)
} | Export-Csv "C:\Evidence\$INCIDENT_ID\powershell-logs.csv"

# Collect Security logs
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4688,4689,4663  # Process creation, termination, object access
    StartTime=(Get-Date).AddHours(-2)
} | Export-Csv "C:\Evidence\$INCIDENT_ID\security-logs.csv"

# Collect Sysmon logs (if available)
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'
    ID=10  # Process access
    StartTime=(Get-Date).AddHours(-2)
} | Export-Csv "C:\Evidence\$INCIDENT_ID\sysmon-logs.csv"

# Check for LSASS access
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'
    ID=10
} | Where-Object {$_.Message -like "*lsass.exe*"} | 
  Select-Object TimeCreated, Message | 
  Export-Csv "C:\Evidence\$INCIDENT_ID\lsass-access.csv"

# List running processes
Get-Process | Select-Object Name, Id, Path, StartTime, Company | 
  Export-Csv "C:\Evidence\$INCIDENT_ID\processes.csv"

# Check for Mimikatz artifacts
Get-ChildItem -Path C:\ -Recurse -Filter "*mimikatz*" -ErrorAction SilentlyContinue |
  Select-Object FullName, CreationTime, LastWriteTime |
  Export-Csv "C:\Evidence\$INCIDENT_ID\mimikatz-files.csv"

# Check recent file modifications
Get-ChildItem -Path C:\Users -Recurse -File |
  Where-Object {$_.LastWriteTime -gt (Get-Date).AddHours(-2)} |
  Select-Object FullName, LastWriteTime |
  Export-Csv "C:\Evidence\$INCIDENT_ID\recent-files.csv"
```

#### Linux System
```bash
# Create incident directory
INCIDENT_ID="INC-$(date +%Y%m%d-%H%M%S)"
mkdir -p /tmp/evidence/$INCIDENT_ID
cd /tmp/evidence/$INCIDENT_ID

# Collect authentication logs
sudo cp /var/log/auth.log* .
sudo cp /var/log/secure* . 2>/dev/null || true

# Check shadow file access
sudo ausearch -f /etc/shadow -ts recent > shadow-access.log

# Check for credential dumping tools
sudo find / -name "*mimikatz*" -o -name "*procdump*" -o -name "*pwdump*" 2>/dev/null > suspicious-files.txt

# Collect running processes
ps auxf > processes.txt
sudo lsof > open-files.txt

# Check bash history for all users
for user in $(cut -d: -f1 /etc/passwd); do
    if [ -f /home/$user/.bash_history ]; then
        echo "=== $user ===" >> bash-histories.txt
        sudo cat /home/$user/.bash_history >> bash-histories.txt
    fi
done

# Package evidence
sudo tar -czf evidence-$INCIDENT_ID.tar.gz *
```

### Determine Scope

**Critical questions:**
1. ☐ Which credentials were likely compromised?
   - Domain admin accounts?
   - Service accounts?
   - Local administrator accounts?
   - Regular user accounts?

2. ☐ What access do these credentials provide?
   - Access to other systems?
   - Access to sensitive data?
   - Administrative privileges?

3. ☐ Is there evidence of credential use?
   - Lateral movement to other systems?
   - Privilege escalation?
   - Data access or exfiltration?

### Check for Lateral Movement

```bash
# Check for new SSH connections from this system
sudo grep "Connection from" /var/log/auth.log | tail -50

# Check for RDP connections (Windows)
# Event ID 4624 (Logon) with Logon Type 10 (RemoteInteractive)
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4624
} | Where-Object {$_.Properties[8].Value -eq 10}

# Check network connections
sudo netstat -tunap | grep ESTABLISHED
```

---

## 🛡️ PHASE 3: CONTAINMENT (5 minutes)

### Immediate Containment

#### 1. Isolate Compromised System
```bash
# Already done in Phase 1, verify:
sudo iptables -L -n | head -10

# If using AWS, update security group
aws ec2 modify-instance-attribute \
  --instance-id i-xxxxx \
  --groups sg-isolated-quarantine
```

#### 2. Disable Compromised Accounts
```bash
# Linux - Disable all non-root accounts
for user in $(awk -F: '$3 >= 1000 {print $1}' /etc/passwd); do
    sudo usermod -L $user
    echo "Locked: $user"
done

# Windows - Disable accounts
$compromisedUsers = @("user1", "user2", "admin")
foreach ($user in $compromisedUsers) {
    Disable-LocalUser -Name $user
    Write-Host "Disabled: $user"
}
```

#### 3. Kill Malicious Processes
```bash
# Linux - Kill suspicious processes
sudo pkill -9 -f "mimikatz|procdump|pwdump"

# Windows - Kill suspicious processes
Get-Process | Where-Object {
    $_.ProcessName -match "mimikatz|procdump|pwdump"
} | Stop-Process -Force
```

#### 4. Block Attacker IP/Account
```bash
# If attacker accessed via SSH
sudo iptables -A INPUT -s ATTACKER_IP -j DROP

# If attacker is internal account, disable immediately
sudo usermod -L attacker_account
```

### Short-Term Containment

#### Reset All Potentially Compromised Credentials
```bash
# Force password reset for all users
# Linux
sudo chage -d 0 username  # Forces change on next login

# Windows
Get-LocalUser | Set-LocalUser -PasswordNeverExpires $false
Get-LocalUser | ForEach-Object {
    $_.PasswordExpired = $true
}
```

#### Revoke Active Sessions
```bash
# Linux - Kill all SSH sessions
sudo pkill -9 sshd

# Windows - Log off all users
query user
logoff SESSION_ID
```

### Long-Term Containment

#### Implement Enhanced Monitoring
```bash
# Enable audit logging for credential access
# Linux - auditd rules
sudo auditctl -w /etc/shadow -p wa -k shadow_access
sudo auditctl -w /etc/passwd -p wa -k passwd_access

# Windows - Enable credential access auditing
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
```

---

## 🧹 PHASE 4: ERADICATION (30 minutes)

### Remove Malware/Tools

```bash
# Linux - Find and remove credential dumping tools
sudo find / -name "*mimikatz*" -delete 2>/dev/null
sudo find / -name "*procdump*" -delete 2>/dev/null
sudo find / -name "*pwdump*" -delete 2>/dev/null

# Windows - Remove tools
Get-ChildItem -Path C:\ -Recurse -Filter "*mimikatz*" -ErrorAction SilentlyContinue | Remove-Item -Force
Get-ChildItem -Path C:\ -Recurse -Filter "*procdump*" -ErrorAction SilentlyContinue | Remove-Item -Force
```

### Rotate ALL Credentials

**This is critical - assume all credentials are compromised:**

#### 1. Domain/Active Directory (if applicable)
```powershell
# Reset krbtgt account password (TWICE, 10 hours apart)
# This invalidates all Kerberos tickets
# Coordinate with AD team - this is disruptive

# Reset service account passwords
$serviceAccounts = @("svc_app1", "svc_db1", "svc_backup")
foreach ($account in $serviceAccounts) {
    $newPassword = ConvertTo-SecureString -String (New-Guid).Guid -AsPlainText -Force
    Set-ADAccountPassword -Identity $account -NewPassword $newPassword -Reset
}
```

#### 2. Local Accounts
```bash
# Linux - Force password change for all users
for user in $(awk -F: '$3 >= 1000 {print $1}' /etc/passwd); do
    sudo passwd -e $user
done

# Windows - Reset all local accounts
Get-LocalUser | ForEach-Object {
    $newPass = ConvertTo-SecureString -String ([System.Web.Security.Membership]::GeneratePassword(20,5)) -AsPlainText -Force
    $_ | Set-LocalUser -Password $newPass
}
```

#### 3. SSH Keys
```bash
# Remove all authorized keys
sudo find /home -name "authorized_keys" -exec rm {} \;
sudo rm /root/.ssh/authorized_keys

# Generate new keys for legitimate users
# Distribute securely via out-of-band method
```

#### 4. Service Accounts & API Keys
```bash
# Rotate database passwords
# Rotate API keys
# Rotate application secrets
# Update configuration files
# Restart affected services
```

### Remove Persistence Mechanisms

```bash
# Check for backdoor accounts
# Linux
awk -F: '$3 == 0 {print $1}' /etc/passwd  # Should only show root

# Windows
Get-LocalUser | Where-Object {$_.SID -like "*-500"}  # Built-in Administrator

# Check for scheduled tasks
# Linux
sudo crontab -l
sudo ls -la /etc/cron.*

# Windows
Get-ScheduledTask | Where-Object {$_.Author -notlike "*Microsoft*"}

# Check for suspicious services
# Linux
sudo systemctl list-units --type=service --state=running

# Windows
Get-Service | Where-Object {$_.Status -eq "Running" -and $_.StartType -eq "Automatic"}
```

---

## 🔄 PHASE 5: RECOVERY (1 hour)

### System Rebuild Decision

**Assess if system rebuild is necessary:**

| Factor | Rebuild Required? |
|--------|-------------------|
| Mimikatz executed with admin privileges | YES |
| LSASS memory dumped | YES |
| Rootkit detected | YES |
| System integrity cannot be verified | YES |
| Only failed attempt (no execution) | NO (but harden) |

### If Rebuilding
```bash
# 1. Document current system configuration
# 2. Backup critical data (after malware scan)
# 3. Rebuild from trusted image
# 4. Apply all security patches
# 5. Restore data from clean backup
# 6. Implement hardening measures
# 7. Verify integrity before production
```

### If Not Rebuilding (Hardening)

#### Linux Hardening
```bash
# Update all packages
sudo apt update && sudo apt upgrade -y

# Install security tools
sudo apt install aide rkhunter chkrootkit -y

# Initialize AIDE
sudo aideinit
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Configure PAM for stronger authentication
sudo nano /etc/pam.d/common-password
# Add: password requisite pam_pwquality.so retry=3 minlen=16

# Enable AppArmor/SELinux
sudo systemctl enable apparmor
sudo systemctl start apparmor
```

#### Windows Hardening
```powershell
# Enable Credential Guard
# Requires UEFI, Secure Boot, and TPM 2.0
Enable-WindowsOptionalFeature -Online -FeatureName IsolatedUserMode -NoRestart
Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -NoRestart

# Enable LSA Protection
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -PropertyType DWORD

# Disable WDigest (prevents cleartext password storage)
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0 -PropertyType DWORD

# Enable Windows Defender Credential Guard
# Via Group Policy or Registry
```

### Restore Services

```bash
# Gradually restore network access
sudo iptables -F  # Flush rules
sudo iptables -P INPUT ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo iptables -P FORWARD ACCEPT

# Re-enable accounts (after password reset)
for user in $(awk -F: '$3 >= 1000 {print $1}' /etc/passwd); do
    sudo usermod -U $user
done

# Restart services
sudo systemctl restart sshd
sudo systemctl restart application-service
```

### Enhanced Monitoring

```bash
# Deploy EDR agent (if not already present)
# Configure enhanced logging
# Set up alerts for credential access
# Implement honeypot accounts
```

---

## 📊 PHASE 6: POST-INCIDENT ACTIVITY (2 hours)

### Incident Report

```markdown
# CRITICAL INCIDENT REPORT: Credential Dumping

## Executive Summary
On [DATE] at [TIME], Wazuh detected credential dumping activity on [SYSTEM]. 
[TOOL NAME] was executed by [USER/ATTACKER], potentially compromising 
[NUMBER] accounts including [PRIVILEGED ACCOUNTS]. The system was immediately 
isolated, all credentials were rotated, and [SYSTEM WAS REBUILT / HARDENED].

## Impact Assessment
- **Credentials Compromised**: [LIST]
- **Systems Potentially Affected**: [LIST]
- **Data Accessed**: [ASSESSMENT]
- **Business Impact**: [CRITICAL/HIGH/MEDIUM]
- **Estimated Cost**: $[AMOUNT]

## Root Cause
- [HOW DID ATTACKER GAIN INITIAL ACCESS?]
- [WHY WAS CREDENTIAL DUMPING SUCCESSFUL?]
- [WHAT CONTROLS FAILED?]

## Response Timeline
- **Detection**: [TIME] (MTTD: X minutes)
- **Isolation**: [TIME] (MTTC: X minutes)
- **Eradication**: [TIME]
- **Recovery**: [TIME] (MTTR: X minutes)

## Lessons Learned
### What Went Well
- Rapid detection and isolation
- Comprehensive credential rotation
- [OTHER POSITIVES]

### What Could Be Improved
- [GAPS IDENTIFIED]
- [PROCESS IMPROVEMENTS NEEDED]

## Recommendations
1. Implement Credential Guard on all Windows systems
2. Deploy EDR solution
3. Implement privileged access management (PAM)
4. Enable MFA for all administrative access
5. Implement least privilege access model
6. Regular credential rotation policy
7. Enhanced monitoring for LSASS access
8. Security awareness training on credential protection
```

### Threat Hunt

**Conduct organization-wide threat hunt:**

```bash
# Search for similar activity across all systems
# Check for:
- Other instances of Mimikatz execution
- LSASS memory dumps
- Suspicious PowerShell activity
- Lateral movement from compromised accounts
- Data exfiltration attempts
```

### Preventive Measures

1. **Technical Controls**
   - Deploy EDR on all endpoints
   - Enable Credential Guard (Windows)
   - Enable LSA Protection
   - Implement PAM solution
   - Deploy honeypot credentials
   - Enable MFA everywhere

2. **Process Improvements**
   - Implement least privilege model
   - Regular credential rotation
   - Privileged account monitoring
   - Security awareness training
   - Incident response drills

3. **Detection Enhancements**
   - Add behavioral analytics
   - Monitor for LSASS access patterns
   - Alert on credential dumping tool execution
   - Implement deception technology

---

## 📚 Additional Resources

### Immediate Response Commands
```bash
# ISOLATE SYSTEM
sudo iptables -P INPUT DROP && sudo iptables -P OUTPUT DROP

# DISABLE ACCOUNTS
sudo usermod -L username

# KILL PROCESSES
sudo pkill -9 -f mimikatz

# COLLECT EVIDENCE
ps auxf > /tmp/processes.txt
sudo tar -czf evidence.tar.gz /var/log/auth.log /var/log/syslog
```

### References
- [MITRE ATT&CK T1003](https://attack.mitre.org/techniques/T1003/)
- [Microsoft: Mitigating Pass-the-Hash Attacks](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management)
- [SANS: Detecting and Responding to Mimikatz](https://www.sans.org/white-papers/)

---

**⚠️ REMEMBER: This is a P1 incident. Speed is critical. Isolate first, investigate later.**

**Version**: 1.0  
**Last Updated**: 2026-01-28  
**Next Review**: 2026-02-28
