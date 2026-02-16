# Incident Response Playbooks

## 📋 Overview

This directory contains **production-ready incident response playbooks** for the Cloud SOC Platform. Each playbook provides step-by-step procedures for responding to specific security incidents detected by our SIEM.

## 🎯 Purpose

These playbooks enable:
- **Consistent Response**: Standardized procedures for all analysts
- **Rapid Triage**: Quick decision-making during incidents
- **Knowledge Transfer**: Training resource for new analysts
- **Compliance**: Documented IR procedures for audits
- **Continuous Improvement**: Lessons learned and updates

## 📚 Available Playbooks

### Critical Incidents (Immediate Response Required)
| Playbook | MITRE Technique | Detection Rules | MTTR Target |
|----------|----------------|-----------------|-------------|
| [Credential Dumping](playbooks/credential-dumping.md) | T1003 | 200070–200072, 200013 | 15 min |

### High Priority Incidents
| Playbook | MITRE Technique | Detection Rules | MTTR Target |
|----------|----------------|-----------------|-------------|
| [SSH Brute Force](playbooks/ssh-brute-force.md) | T1110 | 200001–200003 | 30 min |
| [PowerShell Abuse](playbooks/powershell-abuse.md) | T1059.001 | 200010–200014 | 30 min |
| [Privilege Escalation](playbooks/privilege-escalation.md) | T1548.003 | 200020–200022 | 45 min |

### Medium Priority Incidents
| Playbook | MITRE Technique | Detection Rules | MTTR Target |
|----------|----------------|-----------------|-------------|
| [Persistence Mechanisms](playbooks/persistence.md) | T1053, T1543 | 200060–200063 | 1 hour |
| [macOS Compromise](playbooks/macos-compromise.md) | T1059.004, T1547.011 | 200200–200206 | 1 hour |

## 🔄 Incident Response Lifecycle

All playbooks follow the NIST IR lifecycle:

```
┌─────────────┐
│ Preparation │
└──────┬──────┘
       │
       ▼
┌─────────────────┐
│ Detection &     │
│ Analysis        │◄────────┐
└──────┬──────────┘         │
       │                    │
       ▼                    │
┌─────────────────┐         │
│ Containment,    │         │
│ Eradication &   │         │
│ Recovery        │         │
└──────┬──────────┘         │
       │                    │
       ▼                    │
┌─────────────────┐         │
│ Post-Incident   │─────────┘
│ Activity        │
└─────────────────┘
```

## 📊 Playbook Structure

Each playbook includes:

### 1. Overview
- Incident description
- MITRE ATT&CK mapping
- Severity classification
- Detection rules triggered

### 2. Triage (5 minutes)
- Initial assessment questions
- Severity determination
- Escalation criteria
- Quick containment actions

### 3. Investigation (15-30 minutes)
- Evidence collection steps
- Log analysis procedures
- Scope determination
- Indicator identification

### 4. Containment (10-20 minutes)
- Immediate containment actions
- Short-term containment
- Long-term containment
- System isolation procedures

### 5. Eradication (20-40 minutes)
- Threat removal procedures
- Vulnerability remediation
- System hardening
- Verification steps

### 6. Recovery (30-60 minutes)
- System restoration
- Service resumption
- Monitoring procedures
- Validation steps

### 7. Post-Incident (1-2 hours)
- Incident documentation
- Lessons learned
- Playbook updates
- Metrics collection

## 🚨 Severity Classification

### Critical (P1)
- **Response Time**: Immediate (< 15 minutes)
- **Examples**: Credential dumping, ransomware, active breach
- **Escalation**: Immediate to Incident Commander + CISO
- **After-Hours**: Wake up on-call team

### High (P2)
- **Response Time**: < 30 minutes
- **Examples**: Successful brute force, privilege escalation
- **Escalation**: Tier 2 analyst + Team Lead
- **After-Hours**: Contact on-call within 30 minutes

### Medium (P3)
- **Response Time**: < 1 hour
- **Examples**: Failed brute force, suspicious activity
- **Escalation**: Tier 2 analyst (during business hours)
- **After-Hours**: Document and handle next business day

### Low (P4)
- **Response Time**: < 4 hours
- **Examples**: Policy violations, informational alerts
- **Escalation**: Tier 1 analyst review
- **After-Hours**: Queue for next business day

## 📞 Escalation Matrix

| Role | Contact Method | Response Time | Escalation Criteria |
|------|---------------|---------------|---------------------|
| **Tier 1 Analyst** | Slack, Email | Immediate | All alerts |
| **Tier 2 Analyst** | Phone, Slack | < 15 min | P1, P2, complex P3 |
| **Team Lead** | Phone | < 15 min | P1, P2 |
| **Incident Commander** | Phone | < 10 min | P1 only |
| **CISO** | Phone | < 15 min | P1, data breach |
| **Legal** | Phone | < 30 min | Data breach, compliance |

## 🛠️ Tools & Resources

### Investigation Tools
- **Wazuh Dashboard**: Primary SIEM interface
- **SSH Access**: Direct system investigation
- **Log Analysis**: `grep`, `awk`, `jq`, `tail`
- **Network Tools**: `tcpdump`, `netstat`, `ss`
- **Process Analysis**: `ps`, `top`, `htop`, `lsof`

### Evidence Collection
```bash
# Quick evidence collection script
./tools/collect-evidence.sh <hostname> <incident-id>

# Manual evidence collection
tar -czf evidence-$(date +%Y%m%d-%H%M%S).tar.gz \
  /var/log/auth.log \
  /var/log/syslog \
  /var/ossec/logs/alerts/
```

### Communication Templates
- Incident notification email
- Status update template
- Executive summary template
- Post-incident report template

## 📈 Metrics & KPIs

### Response Metrics
- **MTTD** (Mean Time to Detect): < 2 minutes
- **MTTA** (Mean Time to Acknowledge): < 5 minutes
- **MTTI** (Mean Time to Investigate): < 30 minutes
- **MTTC** (Mean Time to Contain): < 1 hour
- **MTTR** (Mean Time to Recover): < 4 hours

### Quality Metrics
- **False Positive Rate**: < 10%
- **Escalation Accuracy**: > 90%
- **Playbook Adherence**: > 95%
- **Documentation Completeness**: 100%

## 📝 Incident Documentation

### Required Information
1. **Incident ID**: Unique identifier (e.g., INC-2026-0128-001)
2. **Detection Time**: When alert was generated
3. **Response Time**: When analyst acknowledged
4. **Severity**: P1/P2/P3/P4
5. **Affected Systems**: Hostnames, IPs
6. **Detection Rules**: Rule IDs that triggered
7. **Actions Taken**: Timeline of response actions
8. **Resolution**: How incident was resolved
9. **Lessons Learned**: What could be improved

### Incident Report Template
```markdown
# Incident Report: [INC-ID]

## Executive Summary
[Brief 2-3 sentence summary]

## Incident Details
- **Incident ID**: INC-2026-0128-001
- **Severity**: P2 (High)
- **Status**: Resolved
- **Detection Time**: 2026-01-28 14:32:15 UTC
- **Resolution Time**: 2026-01-28 15:45:30 UTC
- **Duration**: 1h 13m

## Timeline
[Detailed timeline of events]

## Impact Assessment
[Systems affected, data accessed, business impact]

## Root Cause
[What caused the incident]

## Response Actions
[What was done to contain and resolve]

## Lessons Learned
[What we learned and will improve]

## Recommendations
[Preventive measures for future]
```

## 🎓 Training & Exercises

### Tabletop Exercises
- Monthly scenario walkthroughs
- Test playbook effectiveness
- Identify gaps and improvements
- Cross-train team members

### Simulated Incidents
- Use attack simulation scripts
- Practice full IR lifecycle
- Measure response times
- Update playbooks based on findings

### New Analyst Onboarding
1. Read all playbooks
2. Shadow experienced analyst
3. Participate in tabletop exercise
4. Handle simulated incident
5. Handle real incident with supervision

## 🔄 Playbook Maintenance

### Review Schedule
- **Monthly**: Review metrics and update procedures
- **Quarterly**: Full playbook review and updates
- **After Each Incident**: Update based on lessons learned
- **Annually**: Complete playbook overhaul

### Version Control
- All playbooks tracked in Git
- Changes require peer review
- Major updates require team lead approval
- Version number in each playbook

### Continuous Improvement
1. Collect feedback from analysts
2. Analyze incident metrics
3. Identify common issues
4. Update playbooks
5. Train team on changes

---

**Last Updated**: 2026-02-15
**Version**: 2.0
**Status**: Production-Ready
