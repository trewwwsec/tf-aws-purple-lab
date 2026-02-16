# Incident Response Playbook: Persistence Mechanisms

## 📋 Playbook Information

| Field | Value |
|-------|-------|
| **Playbook ID** | IR-PB-005 |
| **Version** | 1.0 |
| **Last Updated** | 2026-01-28 |
| **MITRE ATT&CK** | T1053, T1543, T1547, T1546 |
| **Severity** | HIGH (P2) |
| **MTTR Target** | 45 minutes |

## 🚨 Incident Overview

### Description
Persistence consists of techniques that adversaries use to maintain access to systems across restarts, changed credentials, and other interruptions. This playbook covers detection and response to various persistence mechanisms on both Linux and Windows systems.

### Detection Rules
- **Rule 200060**: Cron job created or modified (HIGH)
- **Rule 200061**: Systemd service created (HIGH)
- **Rule 200062**: Windows scheduled task created (HIGH)
- **Rule 200063**: Windows service created (HIGH)
- **Rule 200051**: SSH authorized_keys modified (HIGH)
- **Rule 200053**: Windows Startup folder modified (HIGH)

### Persistence Techniques

#### Linux
| Technique | MITRE ID | Common Locations |
|-----------|----------|------------------|
| Cron Jobs | T1053.003 | /etc/cron.*, /var/spool/cron |
| Systemd Services | T1543.002 | /etc/systemd/system, ~/.config/systemd |
| SSH Keys | T1098.004 | ~/.ssh/authorized_keys |
| Bash Profile | T1546.004 | ~/.bashrc, ~/.profile, /etc/profile.d |
| Init Scripts | T1037.004 | /etc/init.d, /etc/rc.local |

#### Windows
| Technique | MITRE ID | Common Locations |
|-----------|----------|------------------|
| Scheduled Tasks | T1053.005 | Task Scheduler |
| Services | T1543.003 | Services snap-in |
| Registry Run Keys | T1547.001 | HKLM/HKCU\...\Run |
| Startup Folder | T1547.001 | Start Menu\Startup |
| WMI Subscription | T1546.003 | WMI Repository |

---

## ⚡ PHASE 1: TRIAGE (5 minutes)

### Initial Assessment

1. **Identify the persistence mechanism:**
   - Cron/Scheduled Task? → Check schedule and command
   - Service? → Check binary path and startup type
   - SSH Key? → Check key owner and origin
   - Registry? → Check value and target executable

2. **Determine legitimacy:**
   - Was this change authorized?
   - Is the associated binary known/trusted?
   - Was the system recently provisioned/patched?

### Severity Determination

| Indicator | Severity | Action |
|-----------|----------|--------|
| Unknown binary with network activity | **P1 CRITICAL** | Immediate isolation |
| Persistence linked to known malware | **P1 CRITICAL** | Immediate isolation |
| Unauthorized SSH key addition | **P2 HIGH** | Urgent investigation |
| Suspicious scheduled task | **P2 HIGH** | Urgent investigation |
| Unknown service installation | **P2 HIGH** | Urgent investigation |
| Authorized change, poor timing | **P3 MEDIUM** | Standard investigation |

---

## 🔍 PHASE 2: INVESTIGATION

### Linux Investigation

#### Cron Jobs
```bash
# Create evidence directory
INCIDENT_ID="INC-$(date +%Y%m%d-%H%M%S)"
mkdir -p /tmp/evidence/$INCIDENT_ID
cd /tmp/evidence/$INCIDENT_ID

# Check system cron directories
echo "=== System Crontabs ===" > cron-audit.txt
for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    echo "--- $dir ---" >> cron-audit.txt
    ls -la $dir >> cron-audit.txt
    for file in $dir/*; do
        echo "File: $file" >> cron-audit.txt
        cat $file >> cron-audit.txt 2>/dev/null
    done
done

# Check user crontabs
echo "=== User Crontabs ===" >> cron-audit.txt
for user in $(cut -d: -f1 /etc/passwd); do
    sudo crontab -l -u $user 2>/dev/null && echo "User: $user" >> cron-audit.txt
done

# Check /var/spool/cron
sudo ls -la /var/spool/cron/crontabs/ >> cron-audit.txt

# Check for recently modified cron files
find /etc/cron* /var/spool/cron -type f -mtime -7 -ls > recent-cron-changes.txt

# Inspect suspicious cron job binary
file /path/to/suspicious/binary
strings /path/to/suspicious/binary | head -50
sha256sum /path/to/suspicious/binary
```

#### Systemd Services
```bash
# List all services
systemctl list-unit-files --type=service > all-services.txt

# Check custom service directories
ls -la /etc/systemd/system/*.service > custom-services.txt 2>/dev/null
ls -la ~/.config/systemd/user/*.service >> custom-services.txt 2>/dev/null

# Inspect suspicious service
systemctl cat suspicious.service > suspicious-service-config.txt

# Check service binary
EXEC_PATH=$(grep ExecStart /etc/systemd/system/suspicious.service | cut -d= -f2 | cut -d' ' -f1)
file $EXEC_PATH
sha256sum $EXEC_PATH

# Check for recently added services
find /etc/systemd/system /usr/lib/systemd/system -name "*.service" -mtime -7 -ls

# Check if service is enabled
systemctl is-enabled suspicious.service
```

#### SSH Authorized Keys
```bash
# Find all authorized_keys files
sudo find / -name "authorized_keys" 2>/dev/null > ssh-keys-locations.txt

# Check each file
for keyfile in $(cat ssh-keys-locations.txt); do
    echo "=== $keyfile ===" >> ssh-keys-audit.txt
    cat $keyfile >> ssh-keys-audit.txt
    stat $keyfile >> ssh-keys-audit.txt
done

# Check for recent modifications
find /home -name "authorized_keys" -mtime -7 -ls > recent-key-changes.txt
find /root -name "authorized_keys" -mtime -7 -ls >> recent-key-changes.txt

# Analyze suspicious key
# Format: command="" ssh-rsa AAAA... user@host
# Look for:
# - Unknown key fingerprints
# - command="" restrictions (or lack thereof)
# - Keys from unknown hosts
ssh-keygen -l -f /path/to/authorized_keys
```

#### Bash Profile Persistence
```bash
# Check all profile files
for file in ~/.bashrc ~/.profile ~/.bash_profile /etc/profile /etc/bash.bashrc /etc/profile.d/*; do
    if [ -f "$file" ]; then
        echo "=== $file ===" >> profile-audit.txt
        stat $file >> profile-audit.txt
        cat $file >> profile-audit.txt
    fi
done

# Look for suspicious commands
grep -r "curl\|wget\|python\|perl\|nc\|base64" /etc/profile.d/ ~/.bashrc ~/.profile 2>/dev/null > suspicious-profile-commands.txt
```

### Windows Investigation

#### Scheduled Tasks
```powershell
# Create evidence directory
$IncidentId = "INC-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$EvidencePath = "C:\Evidence\$IncidentId"
New-Item -Path $EvidencePath -ItemType Directory

# Get all scheduled tasks
Get-ScheduledTask | Export-Csv "$EvidencePath\all-tasks.csv"

# Get detailed task info
Get-ScheduledTask | ForEach-Object {
    $task = $_
    $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        TaskName = $task.TaskName
        TaskPath = $task.TaskPath
        State = $task.State
        Author = $task.Author
        Execute = $task.Actions.Execute
        Arguments = $task.Actions.Arguments
        LastRunTime = $taskInfo.LastRunTime
        NextRunTime = $taskInfo.NextRunTime
    }
} | Export-Csv "$EvidencePath\task-details.csv"

# Find suspicious tasks (non-Microsoft authors)
Get-ScheduledTask | Where-Object {
    $_.Author -notlike "*Microsoft*" -and
    $_.Author -ne $null
} | Export-Csv "$EvidencePath\non-microsoft-tasks.csv"

# Export specific task XML
$suspicious = "SuspiciousTaskName"
Export-ScheduledTask -TaskName $suspicious | Out-File "$EvidencePath\suspicious-task.xml"

# Check task history
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-TaskScheduler/Operational'
    ID=106,200,201
} -MaxEvents 100 | Export-Csv "$EvidencePath\task-history.csv"
```

#### Windows Services
```powershell
# Get all services
Get-Service | Export-Csv "$EvidencePath\all-services.csv"

# Get detailed service info
Get-WmiObject Win32_Service | Select-Object Name, DisplayName, PathName, StartMode, StartName, State |
  Export-Csv "$EvidencePath\service-details.csv"

# Find services running as SYSTEM from non-standard paths
Get-WmiObject Win32_Service | Where-Object {
    $_.StartName -like "*SYSTEM*" -and
    $_.PathName -notlike "*Windows*" -and
    $_.PathName -notlike "*Microsoft*" -and
    $_.PathName -ne $null
} | Export-Csv "$EvidencePath\suspicious-services.csv"

# Check for recently created services (Event ID 7045)
Get-WinEvent -FilterHashtable @{
    LogName='System'
    ID=7045
    StartTime=(Get-Date).AddDays(-7)
} | Export-Csv "$EvidencePath\new-services.csv"

# Inspect suspicious service binary
$svcPath = "C:\path\to\suspicious.exe"
Get-AuthenticodeSignature $svcPath
Get-FileHash $svcPath
```

#### Registry Run Keys
```powershell
# Check all Run keys
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
)

foreach ($key in $runKeys) {
    if (Test-Path $key) {
        Get-ItemProperty -Path $key | Out-File "$EvidencePath\run-keys.txt" -Append
    }
}

# Monitor registry changes (requires Sysmon)
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'
    ID=12,13,14  # Registry events
} -MaxEvents 100 | Export-Csv "$EvidencePath\registry-changes.csv"
```

#### WMI Event Subscriptions
```powershell
# Check for WMI persistence
Get-WMIObject -Namespace root\Subscription -Class __EventFilter | 
  Out-File "$EvidencePath\wmi-filters.txt"

Get-WMIObject -Namespace root\Subscription -Class __EventConsumer | 
  Out-File "$EvidencePath\wmi-consumers.txt"

Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding | 
  Out-File "$EvidencePath\wmi-bindings.txt"

# PowerShell alternative
Get-CimInstance -Namespace root/subscription -ClassName __EventFilter
Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer
Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer
```

---

## 🛡️ PHASE 3: CONTAINMENT

### Linux Containment

```bash
# Disable suspicious cron job
sudo chmod 000 /etc/cron.d/suspicious_job
sudo mv /etc/cron.d/suspicious_job /etc/cron.d/suspicious_job.disabled

# Stop and disable suspicious service
sudo systemctl stop suspicious.service
sudo systemctl disable suspicious.service
sudo mv /etc/systemd/system/suspicious.service /etc/systemd/system/suspicious.service.disabled
sudo systemctl daemon-reload

# Remove unauthorized SSH key
# First backup, then remove
sudo cp /home/user/.ssh/authorized_keys /home/user/.ssh/authorized_keys.backup
sudo grep -v "suspicious_key_pattern" /home/user/.ssh/authorized_keys > /tmp/clean_keys
sudo mv /tmp/clean_keys /home/user/.ssh/authorized_keys
sudo chmod 600 /home/user/.ssh/authorized_keys

# Kill related processes
ps aux | grep suspicious_binary
sudo kill -9 <PID>

# Block network connectivity if needed
sudo iptables -A OUTPUT -p tcp -d <malicious_ip> -j DROP
```

### Windows Containment

```powershell
# Disable suspicious scheduled task
Disable-ScheduledTask -TaskName "SuspiciousTask"

# Stop and disable suspicious service
Stop-Service -Name "SuspiciousService"
Set-Service -Name "SuspiciousService" -StartupType Disabled

# Remove suspicious Run key entry
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SuspiciousEntry"

# Remove WMI persistence
Get-WMIObject -Namespace root\Subscription -Class __EventFilter -Filter "Name='SuspiciousFilter'" | Remove-WMIObject
Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer -Filter "Name='SuspiciousConsumer'" | Remove-WMIObject
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding | Where-Object {$_.Filter -like "*SuspiciousFilter*"} | Remove-WMIObject

# Kill malicious process
$proc = Get-Process -Name "suspicious"
Stop-Process -Id $proc.Id -Force
```

---

## 🧹 PHASE 4: ERADICATION

### Remove All Persistence

#### Linux
```bash
# Remove malicious binaries
sudo rm -f /path/to/malicious/binary
sudo rm -f /usr/local/bin/backdoor

# Remove all cron persistence
sudo rm -f /etc/cron.d/malicious_*
sudo rm -f /var/spool/cron/crontabs/compromised_user

# Remove service files
sudo rm -f /etc/systemd/system/malicious.service
sudo rm -f /lib/systemd/system/malicious.service
sudo systemctl daemon-reload

# Clean profile files
sudo sed -i '/malicious_command/d' /etc/profile.d/malicious.sh
rm -f /etc/profile.d/malicious.sh

# Remove init script persistence
sudo rm -f /etc/init.d/malicious
sudo update-rc.d malicious remove

# Verify cleanup
find /etc/cron* -newer /tmp/timestamp_file -ls
systemctl list-unit-files | grep -i suspicious
```

#### Windows
```powershell
# Remove scheduled tasks
Unregister-ScheduledTask -TaskName "SuspiciousTask" -Confirm:$false

# Remove service
sc.exe delete "SuspiciousService"

# Remove malicious files
Remove-Item -Path "C:\path\to\malware.exe" -Force

# Clean Registry Run keys
$keysToCheck = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
)
foreach ($key in $keysToCheck) {
    Get-ItemProperty -Path $key | ForEach-Object {
        # Review and remove suspicious entries
    }
}

# Remove Startup folder items
Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\malware.lnk" -Force

# Remove WMI subscriptions (full cleanup)
Get-WMIObject -Namespace root\Subscription -Class __EventFilter | Remove-WMIObject
Get-WMIObject -Namespace root\Subscription -Class __EventConsumer | Remove-WMIObject
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding | Remove-WMIObject
```

---

## 🔄 PHASE 5: RECOVERY

### System Validation

#### Linux
```bash
# Verify no persistence remains
# Check cron
crontab -l
ls -la /etc/cron.*
find /var/spool/cron -type f

# Check services
systemctl list-unit-files --type=service | grep enabled

# Check SSH keys
find /home -name "authorized_keys" -exec cat {} \;

# Check profile files
grep -r "curl\|wget\|nc\|python.*http" /etc/profile.d/ ~/.bashrc ~/.profile

# Verify system binaries
debsums -c  # Debian/Ubuntu
rpm -Va     # RHEL/CentOS
```

#### Windows
```powershell
# Verify no persistence remains
Get-ScheduledTask | Where-Object {$_.State -eq "Ready" -and $_.Author -notlike "*Microsoft*"}
Get-WmiObject Win32_Service | Where-Object {$_.StartMode -eq "Auto" -and $_.PathName -notlike "*Windows*"}
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
Get-CimInstance -Namespace root/subscription -ClassName __EventFilter
```

### Enhanced Monitoring

```bash
# Linux - Add audit rules
sudo auditctl -w /etc/cron.d -p wa -k persistence_cron
sudo auditctl -w /etc/systemd/system -p wa -k persistence_systemd
sudo auditctl -w /root/.ssh/authorized_keys -p wa -k persistence_ssh
```

```powershell
# Windows - Enable advanced auditing
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
# Enable Sysmon for detailed monitoring
```

---

## 📊 PHASE 6: POST-INCIDENT

### Document Findings

**Key Questions:**
1. How was the persistence mechanism installed?
2. What was the associated payload/malware?
3. When was the persistence established?
4. What other systems might be affected?
5. Was data exfiltrated during compromise?

### Preventive Measures

1. **File Integrity Monitoring**
   - Monitor cron directories
   - Monitor systemd directories
   - Monitor SSH authorized_keys
   - Monitor registry Run keys

2. **Least Privilege**
   - Restrict who can create scheduled tasks
   - Restrict service installation permissions
   - Control SSH key management

3. **Application Whitelisting**
   - AppLocker/WDAC for Windows
   - fapolicyd for Linux

4. **Detection Rules**
   - Alert on new scheduled tasks
   - Alert on new services
   - Alert on SSH key additions
   - Alert on WMI subscriptions

---

## 📚 Quick Reference

### Linux Commands
```bash
# List cron jobs
crontab -l && ls -la /etc/cron.*

# List systemd services
systemctl list-unit-files --type=service

# Find SSH keys
find / -name "authorized_keys" 2>/dev/null

# Remove cron job
sudo rm /etc/cron.d/malicious
```

### Windows Commands
```powershell
# List scheduled tasks
Get-ScheduledTask

# Disable task
Disable-ScheduledTask -TaskName "Name"

# Remove task
Unregister-ScheduledTask -TaskName "Name"

# Check Run keys
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

---

**Version**: 1.0  
**Last Updated**: 2026-01-28  
**Next Review**: 2026-02-28
