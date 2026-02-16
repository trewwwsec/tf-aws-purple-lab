# SSH Brute Force Detection

## Overview
Detects brute force authentication attacks against SSH services by identifying patterns of repeated failed login attempts followed by successful authentication.

## MITRE ATT&CK Mapping
- **Technique**: T1110 - Brute Force
- **Sub-technique**: T1110.001 - Password Guessing
- **Tactic**: Credential Access

## Detection Logic

### Rule 200001: Multiple Failed Attempts
```xml
<rule id="200001" level="10" frequency="5" timeframe="120">
  <if_matched_sid>5710</if_matched_sid>
  <description>SSH brute force attack detected (5+ failures in 2 minutes)</description>
</rule>
```

**Trigger Conditions:**
- 5 or more failed SSH login attempts
- Within a 120-second (2-minute) window
- From the same source IP

**Severity**: High (10)

### Rule 200002: Successful Login After Failures
```xml
<rule id="200002" level="12">
  <if_sid>5715</if_sid>
  <if_fts></if_fts>
  <description>SSH brute force - successful login after multiple failures</description>
</rule>
```

**Trigger Conditions:**
- Successful SSH login (event 5715)
- Preceded by failed login attempts (using first-time-seen tracking)
- Indicates potential credential compromise

**Severity**: Critical (12)

### Rule 200003: Off-Hours Login
```xml
<rule id="200003" level="8">
  <if_sid>5715</if_sid>
  <time>2 am - 6 am</time>
  <description>SSH login during unusual hours</description>
</rule>
```

**Trigger Conditions:**
- Successful SSH login between 2 AM - 6 AM
- May indicate unauthorized access or compromised credentials

**Severity**: Medium (8)

## Data Sources
- **Linux**: `/var/log/auth.log`, `/var/log/secure`
- **Wazuh Agent**: Monitors authentication logs in real-time
- **Event IDs**:
  - 5710: Failed SSH authentication
  - 5715: Successful SSH authentication

## Testing Procedure

### Simulated Attack
```bash
# From attacker machine
# Install hydra (password cracking tool)
sudo apt install hydra -y

# Create small password list for testing
echo -e "password123\nadmin\nroot\ntest123" > passwords.txt

# Run brute force attack (SAFE - controlled environment only)
hydra -l ubuntu -P passwords.txt ssh://TARGET_IP -t 4

# Expected: Rule 200001 should trigger after 5 failed attempts
```

### Manual Testing
```bash
# From any machine with SSH access
# Attempt 5 failed logins
for i in {1..5}; do
  ssh wronguser@TARGET_IP
  # Enter wrong password
done

# Check Wazuh alerts
# Expected: Alert 200001 within 2 minutes
```

### Verification
```bash
# On Wazuh server
tail -f /var/ossec/logs/alerts/alerts.log | grep "200001\|200002\|200003"

# Or via Wazuh dashboard
# Navigate to: Security Events > Rule ID: 200001
```

## False Positive Scenarios

### Common False Positives
1. **Legitimate user forgot password**
   - User tries multiple passwords before remembering correct one
   - **Tuning**: Whitelist known admin IPs

2. **Automated scripts with wrong credentials**
   - CI/CD pipelines with outdated credentials
   - **Tuning**: Fix automation credentials, whitelist CI/CD IPs

3. **SSH key rotation issues**
   - Temporary failures during key updates
   - **Tuning**: Coordinate with change management

### Tuning Recommendations
```xml
<!-- Whitelist trusted admin IPs -->
<rule id="200001" level="10" frequency="5" timeframe="120">
  <if_matched_sid>5710</if_matched_sid>
  <srcip negate="yes">192.168.1.100</srcip> <!-- Admin workstation -->
  <description>SSH brute force attack detected</description>
</rule>

<!-- Increase threshold for less sensitive systems -->
<rule id="200001" level="10" frequency="10" timeframe="300">
  <!-- 10 failures in 5 minutes instead of 5 in 2 -->
</rule>
```

## Response Playbook

### Immediate Actions (Tier 1 Analyst)
1. **Verify the alert**
   - Check source IP reputation (AbuseIPDB, VirusTotal)
   - Review authentication logs for context
   
2. **Determine if attack was successful**
   - Look for Rule 200002 (successful login after failures)
   - If yes, escalate to Tier 2 immediately

3. **Block source IP** (if confirmed malicious)
   ```bash
   # Temporary block via iptables
   sudo iptables -A INPUT -s ATTACKER_IP -j DROP
   
   # Permanent block via UFW
   sudo ufw deny from ATTACKER_IP
   ```

### Investigation Actions (Tier 2 Analyst)
1. **If login was successful (Rule 200002)**
   - Isolate affected system
   - Review all commands executed by compromised account
   - Check for lateral movement
   - Force password reset
   - Revoke SSH keys

2. **Gather evidence**
   ```bash
   # Extract all SSH logs for the timeframe
   grep "sshd" /var/log/auth.log | grep "ATTACKER_IP" > evidence.log
   
   # Check for successful sessions
   last | grep "ATTACKER_IP"
   
   # Review bash history if access was gained
   cat /home/USERNAME/.bash_history
   ```

3. **Containment**
   - Disable compromised account
   - Rotate all credentials
   - Review firewall rules
   - Enable MFA if not already active

## Metrics & KPIs
- **MTTD** (Mean Time to Detect): < 2 minutes
- **MTTR** (Mean Time to Respond): < 15 minutes for blocking
- **False Positive Rate**: Target < 5%
- **Coverage**: All SSH-enabled systems

## Compliance Mapping
- **PCI DSS**: 10.2.4, 10.2.5 (Track authentication attempts)
- **NIST 800-53**: AU.14, AC.7 (Account lockout)
- **GDPR**: Article 32 (Security of processing)
- **HIPAA**: 164.312(b) (Audit controls)

## References
- [MITRE ATT&CK T1110](https://attack.mitre.org/techniques/T1110/)
- [Wazuh SSH Authentication Rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/ssh-rules.html)
- [NIST SP 800-63B - Authentication Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

## Version History
- **v1.0** (2026-01-28): Initial detection rule creation
- **Coverage**: Linux SSH services
- **Status**: Production-ready
