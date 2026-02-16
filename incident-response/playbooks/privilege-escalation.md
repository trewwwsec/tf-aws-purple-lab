# Incident Response Playbook: Privilege Escalation

## 📋 Playbook Information

| Field | Value |
|-------|-------|
| **Playbook ID** | IR-PB-004 |
| **Version** | 1.0 |
| **Last Updated** | 2026-01-28 |
| **MITRE ATT&CK** | T1548 - Abuse Elevation Control Mechanism |
| **Severity** | HIGH-CRITICAL (P2-P1) |
| **MTTR Target** | 30 minutes |

## 🚨 Incident Overview

### Description
Privilege escalation occurs when an attacker gains elevated access to resources that are typically protected from an application or user. This playbook covers both Linux and Windows privilege escalation techniques.

### Detection Rules
- **Rule 200020**: Sudo authentication failure (MEDIUM)
- **Rule 200021**: Suspicious sudo command - shell escalation (HIGH)
- **Rule 200022**: Sudo configuration modified (CRITICAL)
- **Rule 200032**: User added to privileged group (HIGH)

### Attack Techniques

#### Linux
| Technique | MITRE ID | Severity |
|-----------|----------|----------|
| Sudo abuse | T1548.003 | HIGH |
| SUID exploitation | T1548.001 | HIGH |
| Kernel exploits | T1068 | CRITICAL |
| Writable /etc/passwd | T1548 | CRITICAL |

#### Windows
| Technique | MITRE ID | Severity |
|-----------|----------|----------|
| Token manipulation | T1134 | HIGH |
| UAC bypass | T1548.002 | HIGH |
| Unquoted service paths | T1574.009 | MEDIUM |
| DLL hijacking | T1574.001 | HIGH |

---

## ⚡ PHASE 1: TRIAGE (5 minutes)

### Initial Assessment

**Linux - Check Alert Type:**
```bash
# What triggered?
# - Sudo abuse? → Check command executed
# - SUID abuse? → Identify binary used
# - User added to group? → Check which group
```

**Windows - Check Alert Type:**
```powershell
# What triggered?
# - UAC bypass? → Check process tree
# - Token manipulation? → Check privileges
# - Service exploitation? → Check service paths
```

### Severity Determination

| Indicator | Severity | Action |
|-----------|----------|--------|
| User added to Domain Admins | **P1 CRITICAL** | Immediate isolation |
| Kernel exploit detected | **P1 CRITICAL** | Immediate isolation |
| Root shell obtained | **P1 CRITICAL** | Immediate isolation |
| Sudo config modified | **P1 CRITICAL** | Urgent investigation |
| SUID binary exploited | **P2 HIGH** | Urgent investigation |
| Failed sudo attempts only | **P3 MEDIUM** | Standard investigation |

---

## 🔍 PHASE 2: INVESTIGATION

### Linux Investigation

#### Check Sudo Activity
```bash
# Create evidence directory
INCIDENT_ID="INC-$(date +%Y%m%d-%H%M%S)"
mkdir -p /tmp/evidence/$INCIDENT_ID
cd /tmp/evidence/$INCIDENT_ID

# Check sudo logs
sudo grep -E "sudo|su" /var/log/auth.log > sudo-activity.log
sudo journalctl _COMM=sudo > sudo-journal.log

# Check specific user's sudo activity
sudo grep "username" /var/log/auth.log | grep sudo

# Check current sudo configuration
sudo cat /etc/sudoers > sudoers-backup.txt
sudo ls -la /etc/sudoers.d/ > sudoers.d-listing.txt

# Check sudo version (known vulnerabilities)
sudo --version

# Check for sudo timestamp (token reuse)
ls -la /var/run/sudo/ts/
```

#### Check SUID/SGID Binaries
```bash
# Find all SUID binaries
sudo find / -perm -4000 -type f 2>/dev/null > suid-binaries.txt

# Find all SGID binaries
sudo find / -perm -2000 -type f 2>/dev/null > sgid-binaries.txt

# Compare with baseline (if available)
# Look for unusual SUID binaries:
# - /tmp/*
# - /home/*
# - Recently created

# Check for writable paths in PATH
echo $PATH | tr ':' '\n' | xargs -I {} ls -ld {} 2>/dev/null
```

#### Check User/Group Changes
```bash
# Check password file for modifications
sudo stat /etc/passwd /etc/shadow /etc/group

# Check for new privileged users
awk -F: '$3 == 0 {print $1}' /etc/passwd  # Should only be root

# Check sudo group members
getent group sudo
getent group wheel
getent group admin

# Check recently added users
sudo grep -E "useradd|adduser|usermod" /var/log/auth.log

# Check for unauthorized SSH keys
for user in $(cut -d: -f1 /etc/passwd); do
    if [ -f /home/$user/.ssh/authorized_keys ]; then
        echo "=== $user ==="
        sudo cat /home/$user/.ssh/authorized_keys
    fi
done
```

#### Check for Kernel Exploits
```bash
# Check kernel version
uname -a

# Check for known vulnerable kernels
# DirtyCow (CVE-2016-5195): < 4.8.3, 4.7.x < 4.7.9, 4.4.x < 4.4.26

# Check running processes for exploit indicators
ps auxf | grep -E "dirty|exploit|pwn"

# Check for suspicious compiled binaries
find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null
```

### Windows Investigation

#### Check Privilege Elevation
```powershell
# Create evidence directory
$IncidentId = "INC-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$EvidencePath = "C:\Evidence\$IncidentId"
New-Item -Path $EvidencePath -ItemType Directory

# Check security event logs for privilege changes
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4672,4673,4674  # Special privileges, sensitive privilege use
} -MaxEvents 100 | Export-Csv "$EvidencePath\privilege-events.csv"

# Check for UAC bypass attempts
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4688
} | Where-Object {$_.Message -like "*eventvwr*" -or $_.Message -like "*fodhelper*"} |
  Export-Csv "$EvidencePath\uac-bypass.csv"

# Check current user privileges
whoami /priv | Out-File "$EvidencePath\current-privileges.txt"

# Check local administrators
Get-LocalGroupMember -Group "Administrators" | Export-Csv "$EvidencePath\local-admins.csv"
```

#### Check Service Vulnerabilities
```powershell
# Check for unquoted service paths
Get-WmiObject -Class Win32_Service | Where-Object {
    $_.PathName -notlike '"*' -and
    $_.PathName -like "* *" -and
    $_.PathName -notlike "C:\Windows\*"
} | Select-Object Name, PathName, StartName | Export-Csv "$EvidencePath\unquoted-paths.csv"

# Check service permissions
Get-WmiObject -Class Win32_Service | ForEach-Object {
    $sddl = (sc.exe sdshow $_.Name 2>$null)
    if ($sddl -match "WD") {  # World Write
        [PSCustomObject]@{
            Name = $_.Name
            Path = $_.PathName
            SDDL = $sddl
        }
    }
} | Export-Csv "$EvidencePath\weak-service-perms.csv"

# Check for writable service binaries
$services = Get-WmiObject -Class Win32_Service
foreach ($svc in $services) {
    $path = ($svc.PathName -split '"')[1]
    if ($path -and (Test-Path $path)) {
        $acl = Get-Acl $path
        # Check for Everyone or Users with Modify rights
    }
}
```

#### Check Token Manipulation
```powershell
# Check for impersonation events
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4648  # Explicit credential logon
} -MaxEvents 50 | Export-Csv "$EvidencePath\impersonation.csv"

# Check running processes with elevated tokens
Get-Process -IncludeUserName | Where-Object {
    $_.UserName -like "*SYSTEM*" -or
    $_.UserName -like "*Administrator*"
} | Export-Csv "$EvidencePath\elevated-processes.csv"
```

---

## 🛡️ PHASE 3: CONTAINMENT

### Linux Containment

```bash
# Disable compromised user account
sudo usermod -L <username>

# Remove from sudo group
sudo gpasswd -d <username> sudo
sudo gpasswd -d <username> wheel

# Kill user sessions
sudo pkill -u <username>

# Lock account
sudo passwd -l <username>

# Reset sudo timestamp
sudo -k

# Restrict sudo access (temporary)
sudo chmod 400 /etc/sudoers

# Remove unauthorized SSH keys
sudo rm /home/<username>/.ssh/authorized_keys
sudo rm /root/.ssh/authorized_keys
```

### Windows Containment

```powershell
# Disable compromised user account
Disable-LocalUser -Name "<username>"

# Remove from Administrators group
Remove-LocalGroupMember -Group "Administrators" -Member "<username>"

# Force logoff
query user
logoff <session_id>

# Disable the account in AD (if domain)
Disable-ADAccount -Identity "<username>"

# Reset password immediately
$password = ConvertTo-SecureString "TempP@ss123!" -AsPlainText -Force
Set-LocalUser -Name "<username>" -Password $password
Set-LocalUser -Name "<username>" -PasswordExpired $true
```

### Network Isolation (If Critical)

```bash
# Linux - Block all network
sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT DROP
sudo iptables -P FORWARD DROP

# Or disconnect network interface
sudo ip link set eth0 down
```

```powershell
# Windows - Enable strict firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
New-NetFirewallRule -DisplayName "Block All Outbound" -Direction Outbound -Action Block
```

---

## 🧹 PHASE 4: ERADICATION

### Linux Eradication

```bash
# Restore sudoers from backup
sudo cp /etc/sudoers.backup /etc/sudoers

# Remove unauthorized SUID binaries
sudo chmod u-s /path/to/suspicious/binary

# Remove unauthorized users
sudo userdel -r <malicious_user>

# Remove from privileged groups
for group in sudo wheel admin; do
    sudo gpasswd -d <user> $group 2>/dev/null
done

# Check and remove backdoors
# Check /etc/passwd for authorized entries
sudo grep -v "^#" /etc/passwd | awk -F: '$3 == 0 {print}'

# Remove suspicious cron jobs
sudo crontab -u <user> -r
sudo rm /etc/cron.d/<suspicious_file>

# Check for modified system binaries
sudo debsums -c 2>/dev/null  # Debian/Ubuntu
sudo rpm -Va 2>/dev/null      # RHEL/CentOS
```

### Windows Eradication

```powershell
# Remove unauthorized admin accounts
Remove-LocalUser -Name "<malicious_user>"

# Remove from AD groups
Remove-ADGroupMember -Identity "Domain Admins" -Members "<user>"

# Fix unquoted service paths
# Quote the path in registry
$svcName = "VulnerableService"
$currentPath = (Get-WmiObject Win32_Service -Filter "Name='$svcName'").PathName
# Update via sc.exe or registry

# Remove unauthorized scheduled tasks
Get-ScheduledTask | Where-Object {$_.Author -notlike "*Microsoft*"} | 
  Unregister-ScheduledTask -Confirm:$false

# Check and restore file permissions
icacls "C:\Program Files" /reset /T
```

### Credential Reset

```bash
# Linux - Force password change for all users
for user in $(awk -F: '$3 >= 1000 {print $1}' /etc/passwd); do
    sudo chage -d 0 $user
done
```

```powershell
# Windows - Reset affected account passwords
$users = Get-LocalUser | Where-Object {$_.Enabled -eq $true}
foreach ($user in $users) {
    Set-LocalUser -Name $user.Name -PasswordExpired $true
}
```

---

## 🔄 PHASE 5: RECOVERY

### System Hardening

#### Linux
```bash
# Restrict sudo access
# Only allow specific commands for specific users
# visudo:
# username ALL=(ALL) NOPASSWD: /usr/bin/specific_command

# Enable sudoers timestamp timeout
# Add to /etc/sudoers:
# Defaults timestamp_timeout=5

# Restrict SUID binaries
# Audit and remove unnecessary SUID bits

# Enable audit logging
sudo auditctl -w /etc/sudoers -p wa -k sudoers_changes
sudo auditctl -w /etc/passwd -p wa -k passwd_changes
sudo auditctl -w /etc/group -p wa -k group_changes
```

#### Windows
```powershell
# Enable UAC to highest level
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2

# Enable Credential Guard (requires compatible hardware)
# Configure via Group Policy

# Implement LAPS for local admin passwords
# https://docs.microsoft.com/en-us/windows-server/identity/laps/laps-overview

# Enable Protected Users group for privileged accounts
Add-ADGroupMember -Identity "Protected Users" -Members "<admin_user>"
```

### Enhanced Monitoring

```bash
# Linux - Monitor sudo usage
sudo auditctl -w /etc/sudoers -p wa -k sudoers_changes
sudo auditctl -w /usr/bin/sudo -p x -k sudo_exec

# Monitor privilege escalation
sudo auditctl -a always,exit -F arch=b64 -S setuid -S setgid -k priv_esc
```

```powershell
# Windows - Enhanced monitoring
# Enable command line logging
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

# Enable PowerShell logging
# Via Group Policy or Registry
```

---

## 📊 PHASE 6: POST-INCIDENT

### Incident Report

```markdown
## Privilege Escalation Incident Report

### Summary
On [DATE], a privilege escalation attack was detected on [SYSTEM].
The attacker [DESCRIPTION OF ATTACK].

### Impact
- Accounts Compromised: [LIST]
- Systems Affected: [LIST]
- Data Accessed: [ASSESSMENT]

### Root Cause
- [HOW DID ESCALATION OCCUR]
- [WHAT VULNERABILITY/MISCONFIGURATION]

### Response Timeline
- Detection: [TIME]
- Containment: [TIME]
- Eradication: [TIME]
- Recovery: [TIME]

### Lessons Learned
1. [LESSON 1]
2. [LESSON 2]
3. [LESSON 3]

### Recommendations
1. Implement least privilege access
2. Regular audit of privileged accounts
3. Enable enhanced monitoring
4. Deploy PAM solution
```

### Preventive Measures

1. **Principle of Least Privilege**
   - Regular access reviews
   - JIT/JEA for privileged access
   - Remove unnecessary admin rights

2. **Privileged Access Management (PAM)**
   - Implement PAM solution
   - Session recording
   - Password vaulting

3. **Monitoring**
   - Real-time alerting on privilege changes
   - SIEM correlation rules
   - User behavior analytics

4. **Hardening**
   - Remove unnecessary SUID/SGID
   - Restrict sudo access
   - Enable UAC
   - Implement LAPS

---

**Version**: 1.0  
**Last Updated**: 2026-01-28  
**Next Review**: 2026-02-28
