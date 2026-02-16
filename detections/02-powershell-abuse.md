# PowerShell Abuse Detection

## Overview
Detects malicious PowerShell usage including encoded commands, download cradles, execution policy bypasses, and credential dumping tools like Mimikatz.

## MITRE ATT&CK Mapping
- **Primary Technique**: T1059.001 - Command and Scripting Interpreter: PowerShell
- **Related Techniques**:
  - T1027 - Obfuscated Files or Information
  - T1105 - Ingress Tool Transfer
  - T1562.001 - Impair Defenses: Disable or Modify Tools
  - T1003.001 - OS Credential Dumping: LSASS Memory
- **Tactic**: Execution, Defense Evasion, Credential Access

## Detection Rules

### Rule 200010: Encoded PowerShell Commands
```xml
<rule id="200010" level="12">
  <if_sid>60009</if_sid>
  <field name="win.eventdata.scriptBlockText" type="pcre2">(?i)-enc.*|encodedcommand|frombase64string</field>
  <description>Encoded PowerShell command detected (obfuscation)</description>
</rule>
```

**Detects:**
- `-EncodedCommand` parameter
- `-enc` (abbreviated form)
- `[System.Convert]::FromBase64String()` usage

**Why it matters:** Attackers encode PowerShell to evade detection and hide malicious intent.

**Severity**: High (12)

### Rule 200011: PowerShell Download Cradle
```xml
<rule id="200011" level="12">
  <if_sid>60009</if_sid>
  <field name="win.eventdata.scriptBlockText" type="pcre2">(?i)iex.*downloadstring|invoke-webrequest.*iex|iwr.*iex|curl.*iex|wget.*iex</field>
  <description>PowerShell download cradle detected (remote code execution)</description>
</rule>
```

**Detects:**
- `IEX (New-Object Net.WebClient).DownloadString('http://...')`
- `Invoke-WebRequest | IEX`
- `curl http://... | iex`

**Why it matters:** Download cradles fetch and execute remote payloads, common in initial access.

**Severity**: High (12)

### Rule 200012: Execution Policy Bypass
```xml
<rule id="200012" level="10">
  <if_sid>60009</if_sid>
  <field name="win.eventdata.scriptBlockText" type="pcre2">(?i)-executionpolicy\s+(bypass|unrestricted)</field>
  <description>PowerShell execution policy bypass detected</description>
</rule>
```

**Detects:**
- `-ExecutionPolicy Bypass`
- `-ExecutionPolicy Unrestricted`

**Why it matters:** Bypassing execution policy allows unsigned/malicious scripts to run.

**Severity**: Medium-High (10)

### Rule 200013: Mimikatz Detection
```xml
<rule id="200013" level="15">
  <if_sid>60009</if_sid>
  <field name="win.eventdata.scriptBlockText" type="pcre2">(?i)mimikatz|invoke-mimikatz|dumpcreds|sekurlsa|kerberos::golden</field>
  <description>Mimikatz credential dumping tool detected (CRITICAL)</description>
</rule>
```

**Detects:**
- Mimikatz binary execution
- `Invoke-Mimikatz` PowerShell module
- Mimikatz commands: `sekurlsa::logonpasswords`, `kerberos::golden`

**Why it matters:** Mimikatz is the #1 post-exploitation tool for credential theft.

**Severity**: Critical (15)

### Rule 200014: Invoke-Expression Patterns
```xml
<rule id="200014" level="10">
  <if_sid>60009</if_sid>
  <field name="win.eventdata.scriptBlockText" type="pcre2">(?i)invoke-expression|iex\s+\(</field>
  <description>PowerShell Invoke-Expression detected (potential code injection)</description>
</rule>
```

**Detects:**
- `Invoke-Expression` cmdlet
- `IEX` alias usage

**Why it matters:** IEX executes arbitrary strings as code, often used in fileless malware.

**Severity**: Medium-High (10)

## Data Sources

### Windows Event Logs
- **Event ID 4104**: PowerShell Script Block Logging
  - Logs the actual script content
  - Must be enabled via GPO
  
- **Event ID 4103**: PowerShell Module Logging
  - Logs cmdlet execution

### Prerequisites
PowerShell logging must be enabled on Windows endpoints:

```powershell
# Enable Script Block Logging via Registry
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
  -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWord

# Enable Module Logging
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
  -Name "EnableModuleLogging" -Value 1 -PropertyType DWord
```

Or via Group Policy:
```
Computer Configuration > Administrative Templates > Windows Components > 
Windows PowerShell > Turn on PowerShell Script Block Logging
```

## Testing Procedures

### Test 1: Encoded Command Detection (Rule 200010)
```powershell
# On Windows endpoint (SAFE - just runs Write-Host)
# Encode a benign command
$command = "Write-Host 'Test Alert'"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)

# Execute encoded command
powershell.exe -EncodedCommand $encodedCommand

# Expected: Rule 200010 alert in Wazuh
```

### Test 2: Download Cradle Detection (Rule 200011)
```powershell
# SAFE test - downloads benign content
IEX (New-Object Net.WebClient).DownloadString('https://example.com')

# Expected: Rule 200011 alert
```

### Test 3: Execution Policy Bypass (Rule 200012)
```powershell
# From command prompt
powershell.exe -ExecutionPolicy Bypass -Command "Write-Host 'Test'"

# Expected: Rule 200012 alert
```

### Test 4: Mimikatz Simulation (Rule 200013)
```powershell
# SAFE - just contains the keyword, doesn't run actual Mimikatz
Write-Host "Testing mimikatz detection"

# Or use Atomic Red Team
Invoke-AtomicTest T1003.001 -TestNumbers 1

# Expected: Rule 200013 alert
```

### Verification
```bash
# On Wazuh server
tail -f /var/ossec/logs/alerts/alerts.log | grep "10001[0-4]"

# Or query via API
curl -k -X GET "https://localhost:55000/security_events" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"rule.id":"10001*"}'
```

## False Positive Scenarios

### Common False Positives

#### 1. Legitimate Admin Scripts
**Scenario**: IT admin uses encoded commands for automation
```powershell
# Legitimate use case
$cred = Get-Credential
Invoke-Command -ComputerName Server01 -Credential $cred -ScriptBlock {...}
```

**Tuning**:
```xml
<!-- Whitelist specific admin accounts -->
<rule id="200010" level="12">
  <if_sid>60009</if_sid>
  <field name="win.eventdata.scriptBlockText" type="pcre2">(?i)-enc.*|encodedcommand</field>
  <field name="win.system.computer" negate="yes">ADMIN-WORKSTATION</field>
  <description>Encoded PowerShell command detected</description>
</rule>
```

#### 2. Software Updates/Installers
**Scenario**: Legitimate software uses PowerShell for installation

**Tuning**: Whitelist known software paths
```xml
<rule id="200011" level="12">
  <if_sid>60009</if_sid>
  <field name="win.eventdata.scriptBlockText" type="pcre2">iex.*downloadstring</field>
  <field name="win.eventdata.path" negate="yes">C:\\Program Files\\TrustedApp</field>
  <description>PowerShell download cradle detected</description>
</rule>
```

#### 3. Security Tools
**Scenario**: Vulnerability scanners or EDR tools use PowerShell

**Tuning**: Whitelist security tool processes
```xml
<!-- Exclude known security tools -->
<rule id="200014" level="10">
  <if_sid>60009</if_sid>
  <field name="win.eventdata.parentImage" negate="yes" type="pcre2">CrowdStrike|SentinelOne|Defender</field>
  <description>Invoke-Expression detected</description>
</rule>
```

## Response Playbook

### Tier 1 Analyst Actions

#### For Rules 200010-200012 (Encoded/Download/Bypass)
1. **Immediate triage**
   - Check user account: Is it a privileged user?
   - Check hostname: Is it a server or workstation?
   - Check time: Business hours or off-hours?

2. **Context gathering**
   ```powershell
   # On Windows endpoint
   # Review recent PowerShell history
   Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 50
   
   # Check running processes
   Get-Process | Where-Object {$_.ProcessName -like "*powershell*"}
   ```

3. **Initial containment** (if suspicious)
   - Isolate endpoint from network
   - Disable user account
   - Escalate to Tier 2

#### For Rule 200013 (Mimikatz - CRITICAL)
1. **IMMEDIATE ESCALATION** - This is a critical incident
2. **Do NOT wait** - Isolate system immediately
3. **Notify Incident Commander**

### Tier 2 Analyst Actions

#### Investigation
```powershell
# Collect PowerShell logs
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | 
  Where-Object {$_.TimeCreated -gt (Get-Date).AddHours(-24)} |
  Export-Csv -Path "C:\Evidence\ps_logs.csv"

# Check for persistence
Get-ScheduledTask | Where-Object {$_.Actions.Execute -like "*powershell*"}

# Review network connections
Get-NetTCPConnection | Where-Object {$_.OwningProcess -in (Get-Process powershell).Id}
```

#### Containment & Eradication
1. Kill malicious PowerShell processes
2. Remove persistence mechanisms
3. Scan for additional malware
4. Force password reset if credentials compromised
5. Review all systems accessed by compromised account

#### Recovery
1. Rebuild system if Mimikatz detected
2. Restore from known-good backup
3. Re-image if necessary
4. Update detection rules based on TTPs observed

## Advanced Hunting Queries

### Wazuh Query (via API)
```json
{
  "query": {
    "bool": {
      "must": [
        {"match": {"rule.id": "10001*"}},
        {"range": {"timestamp": {"gte": "now-24h"}}}
      ]
    }
  }
}
```

### Correlation Rule (Multiple PowerShell Techniques)
```xml
<!-- Alert if 3+ different PowerShell techniques in 10 minutes -->
<rule id="200015" level="15" frequency="3" timeframe="600">
  <if_matched_group>powershell</if_matched_group>
  <description>Multiple PowerShell attack techniques detected (CRITICAL)</description>
  <mitre>
    <id>T1059.001</id>
  </mitre>
</rule>
```

## Metrics & KPIs
- **MTTD**: < 1 minute (real-time detection)
- **MTTR**: < 10 minutes for isolation
- **False Positive Rate**: Target < 10% (higher due to legitimate admin use)
- **Coverage**: All Windows endpoints with PowerShell logging enabled

## Compliance Mapping
- **PCI DSS**: 10.6.1 (Review logs for anomalies)
- **NIST 800-53**: AU.6 (Audit review, analysis, and reporting)
- **GDPR**: Article 32 (Security of processing)
- **HIPAA**: 164.312(b) (Audit controls)

## Recommendations

### Preventive Controls
1. **Application Whitelisting**: Use AppLocker or Windows Defender Application Control
2. **Constrained Language Mode**: Restrict PowerShell to limited functionality
3. **JEA (Just Enough Administration)**: Limit PowerShell capabilities per role
4. **AMSI (Anti-Malware Scan Interface)**: Enable for PowerShell script scanning

### Detective Controls
1. **Enable Script Block Logging** on all Windows systems
2. **Enable Module Logging** for detailed cmdlet tracking
3. **Enable Transcription** to log all PowerShell sessions
4. **Deploy Sysmon** for enhanced process monitoring

## References
- [MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [Microsoft PowerShell Security Best Practices](https://docs.microsoft.com/en-us/powershell/scripting/security/overview)
- [Wazuh Windows Event Log Monitoring](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/windows-events.html)
- [PowerShell ♥ the Blue Team](https://devblogs.microsoft.com/powershell/powershell-the-blue-team/)

## Version History
- **v1.0** (2026-01-28): Initial detection rules
- **Coverage**: Windows PowerShell 5.1+
- **Status**: Production-ready
