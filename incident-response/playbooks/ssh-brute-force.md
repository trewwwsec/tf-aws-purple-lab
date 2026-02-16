# Incident Response Playbook: SSH Brute Force Attack

## 📋 Playbook Information

| Field | Value |
|-------|-------|
| **Playbook ID** | IR-PB-001 |
| **Version** | 1.0 |
| **Last Updated** | 2026-01-28 |
| **MITRE ATT&CK** | T1110 - Brute Force |
| **Severity** | High (P2) |
| **MTTR Target** | 30 minutes |

## 🎯 Incident Overview

### Description
An SSH brute force attack occurs when an attacker attempts to gain unauthorized access to a system by systematically trying multiple username/password combinations against the SSH service.

### Detection Rules
- **Rule 200001**: SSH brute force attack detected (5+ failures in 2 minutes)
- **Rule 200002**: Successful login after multiple failures (CRITICAL)
- **Rule 200003**: Off-hours SSH login (2 AM - 6 AM)

### Indicators of Compromise (IOCs)
- Multiple failed SSH authentication attempts from single IP
- Successful login after failed attempts
- Login from unusual geographic location
- Login during unusual hours
- Use of default/common usernames (root, admin, ubuntu)

---

## ⏱️ PHASE 1: TRIAGE (5 minutes)

### Initial Assessment Questions

**Answer these questions immediately:**

1. ☐ Was the brute force attack successful? (Check for Rule 200002)
2. ☐ What is the source IP address?
3. ☐ What username(s) were targeted?
4. ☐ Is this a production system or test system?
5. ☐ Is the attack still ongoing?
6. ☐ How many failed attempts occurred?

### Quick Actions

```bash
# On Wazuh server - Get alert details
sudo tail -n 100 /var/ossec/logs/alerts/alerts.log | grep "200001\|200002\|200003"

# Identify source IP
sudo grep "sshd" /var/ossec/logs/alerts/alerts.log | grep -oP '\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -rn | head -5
```

### Severity Determination

| Condition | Severity | Action |
|-----------|----------|--------|
| Successful login (Rule 200002) | **CRITICAL (P1)** | Escalate immediately, isolate system |
| Failed attempts only, production system | **HIGH (P2)** | Continue with playbook |
| Failed attempts only, test system | **MEDIUM (P3)** | Block IP, monitor |
| Single failed attempt | **LOW (P4)** | Log and monitor |

### Escalation Criteria

**Escalate to Tier 2 if:**
- ✅ Rule 200002 triggered (successful login after failures)
- ✅ Attack targeting production systems
- ✅ Multiple systems affected
- ✅ Attack from known threat actor IP
- ✅ Sensitive data accessible on target system

**Escalate to Incident Commander if:**
- ✅ Successful compromise confirmed
- ✅ Data exfiltration suspected
- ✅ Multiple production systems compromised

---

## 🔍 PHASE 2: INVESTIGATION (15 minutes)

### Evidence Collection

#### On Wazuh Server
```bash
# Create incident directory
INCIDENT_ID="INC-$(date +%Y%m%d-%H%M%S)"
mkdir -p /tmp/evidence/$INCIDENT_ID
cd /tmp/evidence/$INCIDENT_ID

# Collect Wazuh alerts
sudo grep "200001\|200002\|200003" /var/ossec/logs/alerts/alerts.log > wazuh-alerts.log

# Extract source IPs
grep -oP '\d+\.\d+\.\d+\.\d+' wazuh-alerts.log | sort | uniq > source-ips.txt
```

#### On Affected System
```bash
# SSH to affected system
ssh -i ~/.ssh/cloud-soc-key.pem ubuntu@AFFECTED_SYSTEM_IP

# Collect authentication logs
sudo grep "sshd" /var/log/auth.log > /tmp/ssh-auth.log
sudo grep "Failed password" /var/log/auth.log | tail -50 > /tmp/failed-attempts.log

# Check for successful logins
sudo grep "Accepted password\|Accepted publickey" /var/log/auth.log | tail -20 > /tmp/successful-logins.log

# Check currently logged in users
who > /tmp/current-users.txt
w >> /tmp/current-users.txt

# Check recent login history
last -20 > /tmp/login-history.txt

# Check for suspicious processes
ps auxf > /tmp/processes.txt

# Check network connections
sudo netstat -tunap > /tmp/network-connections.txt

# Package evidence
tar -czf evidence-$INCIDENT_ID.tar.gz /tmp/*.txt /tmp/*.log
```

### Log Analysis

#### Identify Attack Pattern
```bash
# Count failed attempts by IP
sudo grep "Failed password" /var/log/auth.log | \
  grep -oP '\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -rn

# Identify targeted usernames
sudo grep "Failed password" /var/log/auth.log | \
  awk '{print $(NF-5)}' | sort | uniq -c | sort -rn

# Check time range of attack
sudo grep "Failed password" /var/log/auth.log | head -1
sudo grep "Failed password" /var/log/auth.log | tail -1
```

#### Check for Successful Compromise
```bash
# Look for successful login from attacker IP
ATTACKER_IP="<IP_FROM_ALERT>"
sudo grep "$ATTACKER_IP" /var/log/auth.log | grep "Accepted"

# If successful login found, check what they did
sudo grep "$ATTACKER_IP" /var/log/auth.log -A 50

# Check bash history for compromised user
COMPROMISED_USER="<username>"
sudo cat /home/$COMPROMISED_USER/.bash_history | tail -50
```

### Threat Intelligence

```bash
# Check IP reputation (AbuseIPDB)
curl -G https://api.abuseipdb.com/api/v2/check \
  --data-urlencode "ipAddress=$ATTACKER_IP" \
  -H "Key: YOUR_API_KEY" \
  -H "Accept: application/json"

# Check VirusTotal
# Visit: https://www.virustotal.com/gui/ip-address/$ATTACKER_IP

# Check Shodan
# Visit: https://www.shodan.io/host/$ATTACKER_IP

# Check if IP is in known threat feeds
grep "$ATTACKER_IP" /var/ossec/etc/lists/threat-intel.txt
```

### Scope Determination

**Questions to answer:**
1. ☐ How many systems were targeted?
2. ☐ Was any system successfully compromised?
3. ☐ What data is accessible on compromised systems?
4. ☐ Are there signs of lateral movement?
5. ☐ Is the attacker still connected?

---

## 🛡️ PHASE 3: CONTAINMENT (10 minutes)

### Immediate Containment

#### Block Attacker IP (All Systems)
```bash
# On affected system - Immediate block via iptables
sudo iptables -A INPUT -s $ATTACKER_IP -j DROP
sudo iptables -L -n | grep $ATTACKER_IP  # Verify

# Make persistent (Ubuntu/Debian)
sudo apt install iptables-persistent -y
sudo netfilter-persistent save

# Alternative: UFW
sudo ufw deny from $ATTACKER_IP
sudo ufw status | grep $ATTACKER_IP  # Verify
```

#### Kill Active Sessions (If Compromised)
```bash
# Find active SSH sessions from attacker
sudo who | grep $ATTACKER_IP

# Get process ID
ps aux | grep "sshd.*$ATTACKER_IP"

# Kill the session
sudo pkill -9 -t pts/X  # Replace X with terminal number

# Verify session terminated
sudo who
```

#### Disable Compromised Account (If Applicable)
```bash
# Lock the account
sudo usermod -L $COMPROMISED_USER

# Verify account is locked
sudo passwd -S $COMPROMISED_USER

# Kill all processes owned by user
sudo pkill -u $COMPROMISED_USER

# Remove SSH authorized keys
sudo rm /home/$COMPROMISED_USER/.ssh/authorized_keys
```

### Short-Term Containment

#### Network-Level Blocking
```bash
# Add to AWS Security Group (if using AWS)
aws ec2 revoke-security-group-ingress \
  --group-id sg-xxxxx \
  --protocol tcp \
  --port 22 \
  --cidr $ATTACKER_IP/32

# Or block at firewall/WAF level
# Document the block in firewall management system
```

#### Restrict SSH Access
```bash
# Temporarily restrict SSH to known IPs only
sudo nano /etc/ssh/sshd_config

# Add these lines:
# AllowUsers admin@TRUSTED_IP
# DenyUsers *

# Restart SSH (be careful not to lock yourself out!)
sudo systemctl restart sshd
```

### Long-Term Containment

#### Implement Rate Limiting
```bash
# Install fail2ban
sudo apt install fail2ban -y

# Configure fail2ban for SSH
sudo nano /etc/fail2ban/jail.local

# Add:
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600

# Start fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Verify
sudo fail2ban-client status sshd
```

---

## 🧹 PHASE 4: ERADICATION (20 minutes)

### Remove Attacker Access

#### Change All Passwords
```bash
# Force password change for compromised user
sudo passwd $COMPROMISED_USER

# Force password change for all users (if widespread compromise)
sudo chage -d 0 username  # Forces change on next login

# Generate strong password
openssl rand -base64 32
```

#### Rotate SSH Keys
```bash
# Backup old keys
sudo cp -r /home/$USER/.ssh /home/$USER/.ssh.backup

# Generate new SSH key pair
ssh-keygen -t ed25519 -C "incident-response-$(date +%Y%m%d)"

# Remove old authorized keys
sudo rm /home/$USER/.ssh/authorized_keys

# Add only trusted keys
echo "ssh-ed25519 AAAA... trusted-admin@workstation" | \
  sudo tee /home/$USER/.ssh/authorized_keys

# Set proper permissions
sudo chmod 600 /home/$USER/.ssh/authorized_keys
sudo chown $USER:$USER /home/$USER/.ssh/authorized_keys
```

### Remove Malware/Backdoors (If Found)

```bash
# Scan for rootkits
sudo apt install rkhunter chkrootkit -y
sudo rkhunter --check
sudo chkrootkit

# Check for suspicious cron jobs
sudo crontab -l
sudo ls -la /etc/cron.*

# Check for suspicious systemd services
sudo systemctl list-units --type=service --state=running
sudo find /etc/systemd/system -type f -mtime -7

# Check for SUID binaries
sudo find / -perm -4000 -type f 2>/dev/null

# Review startup scripts
sudo ls -la /etc/rc*.d/
sudo cat /etc/rc.local
```

### Patch Vulnerabilities

```bash
# Update system
sudo apt update
sudo apt upgrade -y

# Check SSH configuration
sudo sshd -T | grep -i "permitrootlogin\|passwordauthentication"

# Harden SSH config
sudo nano /etc/ssh/sshd_config

# Recommended settings:
# PermitRootLogin no
# PasswordAuthentication no  # Use keys only
# PubkeyAuthentication yes
# MaxAuthTries 3
# LoginGraceTime 60
# AllowUsers specific-user

# Restart SSH
sudo systemctl restart sshd
```

---

## 🔄 PHASE 5: RECOVERY (30 minutes)

### System Restoration

#### Verify System Integrity
```bash
# Check system files
sudo debsums -c  # Debian/Ubuntu
sudo rpm -Va     # RHEL/CentOS

# Verify critical binaries
sudo md5sum /bin/bash /bin/ls /usr/bin/ssh

# Check for modified system files
sudo find /etc -type f -mtime -1  # Files modified in last 24h
```

#### Restore from Backup (If Necessary)
```bash
# If system integrity is compromised, restore from clean backup
# 1. Identify last known-good backup
# 2. Restore system from backup
# 3. Apply security patches
# 4. Verify integrity before bringing online
```

### Service Resumption

#### Re-enable SSH Access
```bash
# Update security group to allow SSH from trusted IPs only
aws ec2 authorize-security-group-ingress \
  --group-id sg-xxxxx \
  --protocol tcp \
  --port 22 \
  --cidr TRUSTED_IP/32

# Verify SSH is working
ssh -i ~/.ssh/new-key.pem ubuntu@AFFECTED_SYSTEM_IP
```

#### Monitor for Reinfection
```bash
# Enable enhanced logging
sudo nano /etc/ssh/sshd_config
# Set: LogLevel VERBOSE

# Monitor auth logs in real-time
sudo tail -f /var/log/auth.log | grep "sshd"

# Check Wazuh alerts
sudo tail -f /var/ossec/logs/alerts/alerts.log | grep "100"
```

### Validation

**Checklist:**
- ☐ Attacker IP is blocked at all levels
- ☐ All compromised accounts disabled or password changed
- ☐ SSH keys rotated
- ☐ No suspicious processes running
- ☐ No unauthorized cron jobs or services
- ☐ fail2ban is active and configured
- ☐ SSH hardening applied
- ☐ System updates applied
- ☐ Monitoring is active
- ☐ Backups are current

---

## 📊 PHASE 6: POST-INCIDENT ACTIVITY (1 hour)

### Incident Documentation

```markdown
# Incident Report: SSH Brute Force Attack

## Executive Summary
On [DATE] at [TIME], Wazuh detected an SSH brute force attack against [SYSTEM]. 
The attack originated from IP [ATTACKER_IP] and consisted of [NUMBER] failed 
login attempts over [DURATION]. The attack [WAS/WAS NOT] successful. 
[IF SUCCESSFUL: The system was isolated and compromised accounts were disabled.]

## Timeline
- **14:32:15** - Initial detection (Rule 200001 triggered)
- **14:33:00** - Analyst acknowledged alert
- **14:35:00** - Investigation began
- **14:40:00** - Attacker IP blocked
- **14:45:00** - [IF COMPROMISED: Compromised account disabled]
- **15:00:00** - Eradication complete
- **15:30:00** - System restored to service
- **16:00:00** - Post-incident review completed

## Impact Assessment
- **Systems Affected**: [LIST]
- **Data Accessed**: [NONE/LIST]
- **Service Downtime**: [DURATION]
- **Business Impact**: [DESCRIPTION]

## Root Cause
- Weak password policy allowed brute force attack
- SSH exposed to internet without rate limiting
- No fail2ban or similar protection in place

## Response Actions
1. Blocked attacker IP via iptables and security group
2. [IF COMPROMISED: Disabled compromised account]
3. Rotated SSH keys
4. Implemented fail2ban
5. Hardened SSH configuration
6. Updated password policy

## Lessons Learned
### What Went Well
- Detection occurred within 2 minutes
- Response was swift and effective
- No data was exfiltrated

### What Could Be Improved
- Should have had fail2ban configured beforehand
- Password policy was too weak
- SSH should not have been exposed to internet

## Recommendations
1. Implement fail2ban on all systems
2. Enforce strong password policy (16+ characters)
3. Use SSH keys only, disable password authentication
4. Implement VPN or bastion host for SSH access
5. Enable MFA for all administrative access
6. Regular security audits of SSH configurations

## Metrics
- **MTTD**: 2 minutes
- **MTTA**: 1 minute
- **MTTI**: 8 minutes
- **MTTC**: 13 minutes
- **MTTR**: 58 minutes
```

### Lessons Learned

**Conduct a lessons learned session with the team:**

1. **What happened?** (Factual timeline)
2. **Why did it happen?** (Root cause)
3. **What went well?** (Positive aspects)
4. **What could be improved?** (Gaps identified)
5. **What actions will we take?** (Improvements)

### Playbook Updates

**Update this playbook based on findings:**
- Add new detection patterns discovered
- Update containment procedures if needed
- Add new tools or commands that were useful
- Document any edge cases encountered

### Preventive Measures

**Implement these to prevent recurrence:**

1. **Technical Controls**
   - Deploy fail2ban on all systems
   - Implement SSH key-only authentication
   - Enable MFA for administrative access
   - Deploy VPN or bastion host
   - Implement rate limiting at firewall

2. **Process Improvements**
   - Regular security audits
   - Automated compliance checks
   - Quarterly penetration testing
   - Security awareness training

3. **Monitoring Enhancements**
   - Add geolocation-based alerts
   - Implement user behavior analytics
   - Create dashboard for SSH activity
   - Set up automated blocking for known bad IPs

---

## 📚 Additional Resources

### Commands Reference
```bash
# Quick investigation commands
sudo grep "Failed password" /var/log/auth.log | tail -50
sudo grep "Accepted" /var/log/auth.log | tail -20
who
last -20
ps auxf
sudo netstat -tunap

# Quick containment commands
sudo iptables -A INPUT -s ATTACKER_IP -j DROP
sudo ufw deny from ATTACKER_IP
sudo usermod -L username
sudo pkill -u username

# Quick hardening commands
sudo apt install fail2ban -y
sudo systemctl enable fail2ban
sudo nano /etc/ssh/sshd_config
sudo systemctl restart sshd
```

### External References
- [NIST SP 800-61r2: Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
- [MITRE ATT&CK T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)
- [CIS SSH Hardening Guide](https://www.cisecurity.org/)
- [fail2ban Documentation](https://www.fail2ban.org/wiki/index.php/Main_Page)

### Contact Information
- **SOC Team Lead**: [PHONE/EMAIL]
- **Incident Commander**: [PHONE/EMAIL]
- **CISO**: [PHONE/EMAIL]
- **IT Operations**: [PHONE/EMAIL]

---

**Version History:**
- v1.0 (2026-01-28): Initial playbook creation
- Status: Production-Ready
- Next Review: 2026-04-28
