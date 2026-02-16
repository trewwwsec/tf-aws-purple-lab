# Detection Rules

## Overview

Production-ready detection rules for the Cloud SOC Platform, mapped to the MITRE ATT&CK framework. Rules are deployed to Wazuh SIEM and validated through attack simulation.

## Detection Coverage

### Rule Sources

| Source | Rules | ID Range | Description |
|--------|-------|----------|-------------|
| **Custom Rules** | 73 | 200000–200999 | Hand-crafted detections for targeted threats |
| **SOCFortress Community** | 2,153 | Various | Community-maintained ruleset |
| **Total** | **2,226+** | — | Comprehensive multi-platform coverage |

### Coverage by Category (Custom Rules)

| Category | Rules | MITRE Techniques | Severity |
|----------|-------|------------------|----------|
| SSH Brute Force | 3 | T1110, T1078 | High–Critical |
| PowerShell Abuse | 5 | T1059.001, T1027, T1105, T1003.001 | High–Critical |
| Privilege Escalation | 5 | T1548.003, T1078.003 | Medium–Critical |
| Account Management | 4 | T1136.001, T1078.002 | High |
| Persistence | 4 | T1053.003/005, T1543.002/003 | High |
| Credential Access | 3 | T1003.001/002/008 | Critical |
| File Integrity | 4 | T1222.002, T1098.004, T1070.003, T1547.001 | High–Critical |
| Network Activity | 2 | T1071, T1059 | High–Critical |
| Defense Evasion | 3 | T1562.001/004, T1070.001 | High–Critical |
| Lateral Movement | 6 | T1021.001/002/004/006, T1569.002 | Medium–High |
| Exfiltration | 5 | T1041, T1048, T1132, T1567 | High |
| Collection | 3 | T1005, T1552.004, T1555.003 | High |
| Discovery | 5 | T1046, T1082, T1087, T1552.005 | Medium–High |
| macOS Attacks | 7 | T1059.004, T1547.011, T1555.001 | Medium–Critical |

### MITRE ATT&CK Tactics: 11/14 Covered

✅ Initial Access · ✅ Execution · ✅ Persistence · ✅ Privilege Escalation · ✅ Defense Evasion · ✅ Credential Access · ✅ Discovery · ✅ Lateral Movement · ✅ Collection · ✅ Exfiltration · ✅ Command & Control

🔲 Resource Development · 🔲 Reconnaissance · 🔲 Impact (planned)

> For the full technique-level breakdown, see [MITRE Coverage Matrix](../docs/MITRE_COVERAGE.md).

## File Structure

```
detections/
├── README.md                   # This file
├── 01-ssh-brute-force.md       # SSH attack detection rules & testing
├── 02-powershell-abuse.md      # PowerShell malicious usage
├── 03-privilege-escalation.md  # Sudo abuse, group modification
├── 04-macos-attacks.md         # macOS-specific detections

wazuh/custom_rules/
├── local_rules.xml             # Custom rules (200xxx IDs) — deploy this
└── socfortress/                # Community rules (2,153 rules)
```

## Deployment

### Quick Start

```bash
# SSH to Wazuh server
ssh -i ~/.ssh/cloud-soc-key.pem ubuntu@WAZUH_SERVER_IP

# Backup existing rules
sudo cp /var/ossec/etc/rules/local_rules.xml \
  /var/ossec/etc/rules/local_rules.xml.backup.$(date +%Y%m%d)

# Deploy custom rules
sudo cp wazuh/custom_rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo chown root:wazuh /var/ossec/etc/rules/local_rules.xml
sudo chmod 640 /var/ossec/etc/rules/local_rules.xml

# Validate and restart
sudo /var/ossec/bin/wazuh-logtest
sudo systemctl restart wazuh-manager
```

### Verification

```bash
# Confirm rules loaded
sudo grep -c "rule id" /var/ossec/etc/rules/local_rules.xml

# Monitor real-time alerts
sudo tail -f /var/ossec/logs/alerts/alerts.log
```

## Testing

Run attack simulation scripts to validate each detection:

```bash
# On target endpoint
cd attack-simulation/
./ssh-brute-force.sh           # Tests rules 200001–200003
./privilege-escalation.sh      # Tests rules 200020–200022
./apt-full-killchain.sh        # Full APT29 kill chain
```

| Simulation | Expected Alert | Time to Alert | Severity |
|------------|----------------|---------------|----------|
| SSH Brute Force | 200001 | < 2 min | High |
| PowerShell Encoded | 200010 | < 10 sec | High |
| Sudo Abuse | 200021 | < 10 sec | High |
| LSASS Access | 200071 | < 10 sec | Critical |
| Shadow File Access | 200070 | < 10 sec | Critical |

## Tuning

### Common Adjustments

**Whitelist trusted IPs** (SSH brute force):
```xml
<rule id="200001" level="10" frequency="5" timeframe="120">
  <if_matched_sid>5710</if_matched_sid>
  <srcip negate="yes">192.168.1.100</srcip>
  <description>SSH brute force attack detected</description>
</rule>
```

**Exclude automation accounts** (Sudo):
```xml
<rule id="200021" level="10">
  <if_sid>200020</if_sid>
  <field name="user" negate="yes">ansible|puppet|chef</field>
  <description>Suspicious sudo command executed</description>
</rule>
```

### Tuning Timeline

| Week | False Positive Rate | Focus |
|------|-------------------|-------|
| 1 | 20–30% | Baseline establishment |
| 2 | 10–15% | Whitelist legitimate activity |
| 3 | 5–10% | Refine regex, adjust thresholds |
| 4 | < 10% | Production-ready |

## Alert Severity & Response

| Level | Severity | Response Time | Action |
|-------|----------|---------------|--------|
| 3–5 | Informational | 24 hours | Review during daily triage |
| 6–9 | Medium | 4 hours | Investigate, document |
| 10–12 | High | 1 hour | Immediate investigation |
| 13–15 | Critical | 15 minutes | Immediate escalation |

## Compliance Mapping

| Framework | Controls Covered |
|-----------|-----------------|
| **PCI DSS** | 10.2.1, 10.2.2, 10.2.4, 10.2.5, 10.6.1, 11.5 |
| **NIST 800-53** | AU.6, AU.14, AC.2, AC.6, AC.7, SI.7 |
| **GDPR** | Article 32, Article 35.7.d |
| **HIPAA** | 164.312(a)(2)(i), 164.312(b) |

## References

- [Wazuh Rule Syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/index.html)
- [MITRE ATT&CK Enterprise](https://attack.mitre.org/matrices/enterprise/)
- [MITRE Coverage Matrix](../docs/MITRE_COVERAGE.md) (full technique list)
- [Sigma Rules](https://github.com/SigmaHQ/sigma)

---

**Last Updated**: 2026-02-15
**Version**: 2.0
**Status**: Production-Ready
