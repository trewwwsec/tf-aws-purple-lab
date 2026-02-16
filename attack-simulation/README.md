# Attack Simulation Framework

## Overview

Safe, controlled attack simulation scripts for validating the Cloud SOC Platform's 2,226+ detection rules. Includes individual technique scripts, cross-platform macOS tests, and a full APT29 kill chain orchestrator.

⚠️ **WARNING**: These scripts simulate real attack techniques. **ONLY** run them in your isolated lab environment. **NEVER** run on production systems or systems you don't own.

## 📋 Simulation Coverage

### MITRE ATT&CK Techniques Simulated

| Technique | Name | Scripts | Detection Rules |
|-----------|------|---------|----------------|
| T1110 | Brute Force | `ssh-brute-force.sh` | 200001–200003 |
| T1059.001 | PowerShell | `powershell-attacks.ps1` | 200010–200014 |
| T1548.003 | Sudo Abuse | `privilege-escalation.sh` | 200020–200022 |
| T1003 | Credential Dumping | `apt-credential-harvest.sh` | 200070–200072 |
| T1021 | Lateral Movement | `apt-lateral-movement.sh` | 200090–200094 |
| T1041/T1048 | C2 & Exfiltration | `apt-c2-exfil.sh` | 200050–200054 |
| T1059.004 | macOS Shell | `macos-attacks.sh` | 200200–200206 |
| **Full Chain** | APT29 Kill Chain | `apt-full-killchain.sh` | All of the above |

## 🚀 Quick Start

### Prerequisites
- ✅ Wazuh server deployed and running
- ✅ Wazuh agents installed on test endpoints
- ✅ Detection rules deployed
- ✅ SSH access to endpoints
- ✅ Admin/sudo privileges on test systems

### Running Simulations

#### Linux Endpoint
```bash
# SSH to Linux endpoint
ssh -i ~/.ssh/cloud-soc-key.pem ubuntu@LINUX_ENDPOINT_IP

# Clone this repository
git clone https://github.com/trewwwsec/tf-aws-soc.git
cd tf-aws-soc/attack-simulation

# Run individual simulation
./ssh-brute-force.sh

# Or run all Linux simulations
./run-all-linux.sh
```

#### Windows Endpoint
```powershell
# RDP to Windows endpoint
# Clone repository or copy scripts

# Run individual simulation
.\powershell-attacks.ps1

# Or run all Windows simulations
.\run-all-windows.ps1
```

## Scripts

### Individual Technique Scripts
| Script | Platform | Techniques |
|--------|----------|------------|
| `ssh-brute-force.sh` | Linux | T1110 Brute Force |
| `privilege-escalation.sh` | Linux | T1548.003 Sudo Abuse |
| `powershell-attacks.ps1` | Windows | T1059.001 PowerShell |
| `macos-attacks.sh` | macOS | T1059.004, T1547.011, T1555.001 |

### APT29 Kill Chain Suite
| Script | Phase | Description |
|--------|-------|-------------|
| `apt-credential-harvest.sh` | Credential Access | Shadow/passwd dumping, key theft |
| `apt-lateral-movement.sh` | Lateral Movement | SSH pivoting, remote execution |
| `apt-c2-exfil.sh` | C2 & Exfiltration | Beaconing, data staging, DNS exfil |
| `apt-full-killchain.sh` | **Full Chain** | Orchestrates all phases across victims |

### Support
| Script | Purpose |
|--------|--------|
| `common.sh` | Shared utilities (colors, logging, cleanup) |
| `run-all-linux.sh` | Execute all Linux simulations |

## 🧪 Testing Workflow

### 1. Pre-Test Preparation
```bash
# On Wazuh server - Start monitoring alerts
tail -f /var/ossec/logs/alerts/alerts.log | grep "Rule: 100"
```

### 2. Run Simulation
```bash
# On target endpoint
./ssh-brute-force.sh
```

### 3. Verify Detection
```bash
# Check for expected alerts in Wazuh dashboard
# Or via command line on Wazuh server
sudo grep "200001" /var/ossec/logs/alerts/alerts.log
```

### 4. Document Results
```bash
# Record in test results
echo "Test: SSH Brute Force | Status: PASS | Alert: 200001" >> test-results.txt
```

## 📈 Expected Results

### Alert Generation Timeline
| Simulation | Expected Alert | Time to Alert | Severity |
|------------|----------------|---------------|----------|
| SSH Brute Force | 200001 | < 2 minutes | High |
| PowerShell Encoded | 200010 | < 10 seconds | High |
| Sudo Abuse | 200021 | < 10 seconds | High |
| Shadow File Access | 200070 | < 10 seconds | Critical |
| Lateral Movement | 200090 | < 10 seconds | Medium |
| APT Full Kill Chain | Multiple | < 5 minutes | Critical |

## 🔒 Safety Measures

### Built-in Safeguards
1. **Confirmation Prompts**: All scripts require confirmation before execution
2. **Cleanup Functions**: Automatic cleanup of test artifacts
3. **Logging**: All actions logged for audit trail
4. **Reversible**: All changes can be reverted
5. **Isolated**: Designed for isolated lab environments only

### Safety Checklist
- [ ] Running in isolated lab environment
- [ ] Not connected to production networks
- [ ] Have backups of test systems
- [ ] Wazuh monitoring is active
- [ ] Have documented rollback procedures
- [ ] Team is aware of testing schedule

## 📝 Documentation

Each simulation script includes:
- ✅ MITRE ATT&CK technique mapping
- ✅ Expected detection rules triggered
- ✅ Step-by-step execution details
- ✅ Cleanup procedures
- ✅ Troubleshooting guidance
- ✅ Safety warnings

## 🎓 Learning Objectives

By running these simulations, you will:
1. **Validate Detection Rules**: Confirm rules trigger as expected
2. **Understand Attack Techniques**: Learn how real attacks work
3. **Practice Incident Response**: Respond to simulated incidents
4. **Tune Detection Rules**: Identify and fix false positives/negatives
5. **Build Confidence**: Gain hands-on experience with attack techniques

## 🔄 Continuous Improvement

### After Each Simulation
1. Document results (pass/fail)
2. Note any unexpected behavior
3. Tune detection rules if needed
4. Update response playbooks
5. Improve simulation scripts

### Metrics to Track
- **Detection Rate**: % of simulations that triggered alerts
- **False Negatives**: Simulations that didn't trigger expected alerts
- **Time to Detect**: How quickly alerts were generated
- **Alert Quality**: Were alerts actionable and accurate?

## 🚨 Incident Response Integration

### Simulated Incident Workflow
1. **Detection**: Alert generated by Wazuh
2. **Triage**: Analyst reviews alert
3. **Investigation**: Follow response playbook
4. **Containment**: Execute containment steps (simulated)
5. **Documentation**: Create incident report
6. **Lessons Learned**: Update procedures

### Practice Scenarios
- **Scenario 1**: SSH brute force with successful login
- **Scenario 2**: PowerShell-based credential dumping
- **Scenario 3**: Privilege escalation to root
- **Scenario 4**: Persistence via scheduled tasks
- **Scenario 5**: Multi-stage attack chain

## 📊 Reporting

### Test Report Template
```markdown
# Attack Simulation Test Report

**Date**: YYYY-MM-DD
**Tester**: Your Name
**Environment**: Lab/Test

## Tests Executed
1. SSH Brute Force - PASS ✅
2. PowerShell Encoded - PASS ✅
3. Sudo Abuse - FAIL ❌ (No alert generated)

## Issues Found
- Rule 200021 not triggering for sudo bash
- Need to adjust regex pattern

## Recommendations
- Update rule 200021 regex
- Add additional test cases
- Increase logging verbosity
```

## 🔗 References

### Atomic Red Team
- [Official Repository](https://github.com/redcanaryco/atomic-red-team)
- [Atomic Red Team Docs](https://atomicredteam.io/)
- [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam)

### MITRE ATT&CK
- [Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [Technique Descriptions](https://attack.mitre.org/techniques/enterprise/)

### Additional Resources
- [MITRE Cyber Analytics Repository](https://car.mitre.org/)
- [Detection Lab](https://github.com/clong/DetectionLab)
- [Purple Team Exercise Framework](https://github.com/scythe-io/purple-team-exercise-framework)

## ⚖️ Legal & Ethical Considerations

### Important Disclaimers
- ⚠️ **Authorization Required**: Only test on systems you own or have explicit permission to test
- ⚠️ **Isolated Environment**: Use isolated lab environments, not production
- ⚠️ **No Malicious Intent**: These scripts are for defensive security testing only
- ⚠️ **Compliance**: Ensure testing complies with organizational policies
- ⚠️ **Liability**: User assumes all responsibility for proper use

### Best Practices
1. Document all testing activities
2. Obtain written authorization
3. Schedule testing during maintenance windows
4. Notify relevant stakeholders
5. Have rollback procedures ready
6. Monitor for unintended impacts

---

**Last Updated**: 2026-02-15
**Version**: 2.0
**Status**: Production-Ready
