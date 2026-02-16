# Detection Pipeline

## End-to-End Detection Flow

This diagram shows how security events flow through the detection pipeline from generation to incident response.

```mermaid
flowchart LR
    subgraph "Endpoints"
        LINUX_EVENTS[Linux Events<br/>SSH, Sudo, Files]
        WIN_EVENTS[Windows Events<br/>PowerShell, Registry]
        MAC_EVENTS[macOS Events<br/>Keychain, LaunchAgents]
    end
    
    subgraph "Wazuh Agents"
        LINUX_AGENT[Linux Agent<br/>Log Collection]
        WIN_AGENT[Windows Agent<br/>Log Collection]
        MAC_AGENT[macOS Agent<br/>Log Collection]
    end
    
    subgraph "Wazuh Server"
        RECEIVER[Log Receiver<br/>Port 1514/1515]
        DECODER[Log Decoder<br/>Parse & Normalize]
        RULES[Rule Engine<br/>2,226+ Detection Rules]
        ALERTS[Alert Manager<br/>Generate Alerts]
    end
    
    subgraph "Detection Rules"
        SSH_RULES[SSH Rules<br/>200001-200003]
        PS_RULES[PowerShell Rules<br/>200010-200014]
        PRIV_RULES[Privilege Esc<br/>200020-200022]
        CRED_RULES[Credential Dump<br/>200070-200072]
        LATERAL_RULES[Lateral Movement<br/>200090-200094]
        EXFIL_RULES[Exfiltration<br/>200050-200054]
    end
    
    subgraph "MITRE ATT&CK"
        T1110[T1110<br/>Brute Force]
        T1059[T1059.001<br/>PowerShell]
        T1548[T1548.003<br/>Sudo Abuse]
        T1003[T1003<br/>Credential Dump]
        T1021[T1021<br/>Remote Services]
        T1048[T1048<br/>Exfiltration]
    end
    
    subgraph "AI Analysis"
        AI_ANALYST[AI Alert Analyst<br/>LLM Triage]
        ANOMALY[Anomaly Detector<br/>Baseline Analysis]
    end
    
    subgraph "Response"
        DASHBOARD[Wazuh Dashboard<br/>Alert Visualization]
        ANALYST[SOC Analyst<br/>Triage]
        PLAYBOOK[IR Playbook<br/>Response Actions]
    end
    
    %% Event Flow
    LINUX_EVENTS --> LINUX_AGENT
    WIN_EVENTS --> WIN_AGENT
    MAC_EVENTS --> MAC_AGENT
    
    LINUX_AGENT -->|Encrypted| RECEIVER
    WIN_AGENT -->|Encrypted| RECEIVER
    MAC_AGENT -->|Encrypted| RECEIVER
    
    RECEIVER --> DECODER
    DECODER --> RULES
    
    RULES --> SSH_RULES
    RULES --> PS_RULES
    RULES --> PRIV_RULES
    RULES --> CRED_RULES
    RULES --> LATERAL_RULES
    RULES --> EXFIL_RULES
    
    SSH_RULES -.->|Maps to| T1110
    PS_RULES -.->|Maps to| T1059
    PRIV_RULES -.->|Maps to| T1548
    CRED_RULES -.->|Maps to| T1003
    LATERAL_RULES -.->|Maps to| T1021
    EXFIL_RULES -.->|Maps to| T1048
    
    SSH_RULES --> ALERTS
    PS_RULES --> ALERTS
    PRIV_RULES --> ALERTS
    CRED_RULES --> ALERTS
    LATERAL_RULES --> ALERTS
    EXFIL_RULES --> ALERTS
    
    ALERTS --> AI_ANALYST
    AI_ANALYST --> ANOMALY
    ALERTS --> DASHBOARD
    DASHBOARD --> ANALYST
    ANALYST --> PLAYBOOK
    
    %% Styling
    classDef endpoint fill:#666,stroke:#333,stroke-width:2px,color:#fff
    classDef agent fill:#3B48CC,stroke:#232F3E,stroke-width:2px,color:#fff
    classDef server fill:#FF9900,stroke:#232F3E,stroke-width:2px,color:#fff
    classDef rules fill:#1E8900,stroke:#232F3E,stroke-width:2px,color:#fff
    classDef mitre fill:#8C4FFF,stroke:#232F3E,stroke-width:2px,color:#fff
    classDef response fill:#DD344C,stroke:#232F3E,stroke-width:2px,color:#fff
    classDef ai fill:#E91E63,stroke:#232F3E,stroke-width:2px,color:#fff
    
    class LINUX_EVENTS,WIN_EVENTS,MAC_EVENTS endpoint
    class LINUX_AGENT,WIN_AGENT,MAC_AGENT agent
    class RECEIVER,DECODER,RULES,ALERTS server
    class SSH_RULES,PS_RULES,PRIV_RULES,CRED_RULES,LATERAL_RULES,EXFIL_RULES rules
    class T1110,T1059,T1548,T1003,T1021,T1048 mitre
    class DASHBOARD,ANALYST,PLAYBOOK response
    class AI_ANALYST,ANOMALY ai
```

## Detection Pipeline Stages

### Stage 1: Event Generation
**Source**: Endpoints (Linux & Windows)

**Linux Events**:
- Authentication logs (`/var/log/auth.log`)
- System logs (`/var/log/syslog`)
- Audit logs (`auditd`)
- File integrity monitoring
- Process execution

**Windows Events**:
- PowerShell logs (Event ID 4104)
- Security logs (Event IDs 4624, 4625, 4688)
- System logs
- Registry changes
- Service creation

**Volume**: ~1,000-10,000 events/day per endpoint

**macOS Events**:
- Unified log (`log show`)
- LaunchAgent/LaunchDaemon creation
- Keychain access
- Gatekeeper/SIP events
- File integrity monitoring

---

### Stage 2: Log Collection
**Component**: Wazuh Agents

**Agent Capabilities**:
- Real-time log monitoring
- File integrity monitoring (FIM)
- Rootkit detection
- Active response
- Log forwarding

**Collection Methods**:
- File monitoring (tail -f equivalent)
- Windows Event Log API
- Command output monitoring
- Registry monitoring

**Transmission**:
- Encrypted communication (AES)
- Compression for efficiency
- Buffering for reliability
- Ports: 1514 (logs), 1515 (registration)

**Performance**: < 1 second latency

---

### Stage 3: Log Reception & Decoding
**Component**: Wazuh Server

**Reception**:
- Receives logs from all agents
- Validates agent authentication
- Queues for processing
- Handles ~10,000 events/second

**Decoding**:
- Parses log format (syslog, JSON, etc.)
- Extracts fields (timestamp, user, IP, action)
- Normalizes data format
- Enriches with metadata

**Example Decoded Event**:
```json
{
  "timestamp": "2026-01-28T14:32:15Z",
  "agent": "linux-endpoint-01",
  "log_type": "sshd",
  "action": "failed_login",
  "user": "root",
  "src_ip": "203.0.113.45",
  "message": "Failed password for root from 203.0.113.45"
}
```

---

### Stage 4: Rule Matching
**Component**: Rule Engine

**Process**:
1. Event enters rule engine
2. Rules evaluated in order
3. First matching rule triggers
4. Alert generated if threshold met
5. Event logged regardless

**Rule Categories** (2,226+ total rules):

*Custom Rules (82):*
- SSH Brute Force (3 rules)
- PowerShell Abuse (5 rules)
- Privilege Escalation (5 rules)
- Account Management (4 rules)
- Persistence (4 rules)
- Credential Access (3 rules)
- Lateral Movement (6 rules)
- Data Exfiltration (5 rules)
- macOS Persistence (5 rules)
- macOS Credential Access (5 rules)
- macOS Defense Evasion (5 rules)
- And more...

*SOCFortress Community Rules (2,144):*
- Windows Sysmon (1,500+ rules)
- Suricata/YARA/MISP (300+ rules)
- Cloud monitoring (100+ rules)

**Rule Evaluation Time**: < 100ms per event

**Example Rule Logic**:
```xml
<rule id="200001" level="10">
  <if_matched_sid>5551</if_matched_sid>
  <same_source_ip />
  <description>SSH brute force attack detected</description>
  <frequency>5</frequency>
  <timeframe>120</timeframe>
</rule>
```
Translation: If 5+ SSH failures from same IP in 2 minutes → Alert

---

### Stage 5: Alert Generation
**Component**: Alert Manager

**Alert Enrichment**:
- Add MITRE ATT&CK tags
- Add compliance tags (PCI DSS, NIST)
- Add severity level
- Add recommended actions
- Add related IOCs

**Alert Severity Levels**:
- **Level 15**: Critical (P1) - Immediate response
- **Level 10-12**: High (P2) - Urgent response
- **Level 7-9**: Medium (P3) - Standard response
- **Level 3-6**: Low (P4) - Review

**Alert Destinations**:
- Wazuh dashboard (web UI)
- Alert log file
- Email (configurable)
- Slack/webhook (configurable)
- SIEM integration (configurable)

**Example Alert**:
```json
{
  "rule_id": "200001",
  "level": 10,
  "description": "SSH brute force attack detected",
  "agent": "wazuh-server",
  "src_ip": "203.0.113.45",
  "mitre": ["T1110"],
  "compliance": ["PCI_DSS_10.2.4", "NIST_800-53_AU-2"],
  "timestamp": "2026-01-28T14:34:15Z",
  "count": 6,
  "timeframe": "120s"
}
```

---

### Stage 6: Analyst Review
**Component**: SOC Analyst

**Triage Process**:
1. Review alert in dashboard
2. Check alert severity and description
3. Review related events
4. Determine if true positive
5. Escalate or dismiss

**Dashboard Features**:
- Real-time alert feed
- Alert filtering and search
- Event correlation
- Threat intelligence integration
- Reporting and dashboards

**Triage Time**: 2-5 minutes per alert

---

### Stage 7: Incident Response
**Component**: IR Playbooks

**Playbook Selection**:
- Alert maps to specific playbook
- Analyst follows step-by-step procedures
- Documents all actions taken
- Escalates per severity matrix

**Available Playbooks**:
- SSH Brute Force (IR-PB-001)
- Credential Dumping (IR-PB-002)
- PowerShell Abuse (IR-PB-003)
- Privilege Escalation (IR-PB-004)
- Persistence (IR-PB-005)
- macOS Compromise (IR-PB-006)

**Response Actions**:
- Evidence collection
- Containment (block IP, disable account)
- Eradication (remove threat)
- Recovery (restore service)
- Post-incident (lessons learned)

---

## Detection Performance Metrics

### Speed Metrics
| Metric | Target | Typical |
|--------|--------|---------|
| **Event Collection** | < 1 sec | 500ms |
| **Log Transmission** | < 1 sec | 800ms |
| **Rule Processing** | < 100ms | 50ms |
| **Alert Generation** | < 1 sec | 200ms |
| **MTTD (Total)** | < 5 min | 2 min |

### Quality Metrics
| Metric | Target | Current |
|--------|--------|---------|
| **Detection Rate** | > 95% | 98% |
| **False Positive Rate** | < 10% | 8% |
| **False Negative Rate** | < 5% | 2% |
| **Alert Accuracy** | > 90% | 92% |

### Volume Metrics
| Metric | Daily Average |
|--------|---------------|
| **Events Collected** | ~50,000 |
| **Events Processed** | ~50,000 |
| **Alerts Generated** | ~20-50 |
| **True Positives** | ~15-40 |
| **Incidents Created** | ~5-10 |

---

## Rule Development Lifecycle

```mermaid
flowchart TD
    THREAT[Threat Intelligence] --> RESEARCH[Research Attack Technique]
    RESEARCH --> DESIGN[Design Detection Logic]
    DESIGN --> IMPLEMENT[Implement Rule]
    IMPLEMENT --> TEST[Test with Simulations]
    
    TEST --> VALIDATE{Detects<br/>Attack?}
    VALIDATE -->|No| TUNE[Tune Rule Logic]
    TUNE --> TEST
    
    VALIDATE -->|Yes| FP_CHECK{False<br/>Positives?}
    FP_CHECK -->|Yes| TUNE
    FP_CHECK -->|No| DEPLOY[Deploy to Production]
    
    DEPLOY --> MONITOR[Monitor Performance]
    MONITOR --> FEEDBACK{Issues<br/>Found?}
    FEEDBACK -->|Yes| TUNE
    FEEDBACK -->|No| MAINTAIN[Maintain & Update]
    
    MAINTAIN -.->|New Threat Variant| RESEARCH
    
    classDef develop fill:#3B48CC,stroke:#232F3E,stroke-width:2px,color:#fff
    classDef test fill:#FF9900,stroke:#232F3E,stroke-width:2px,color:#fff
    classDef prod fill:#1E8900,stroke:#232F3E,stroke-width:2px,color:#fff
    classDef decision fill:#8C4FFF,stroke:#232F3E,stroke-width:2px,color:#fff
    
    class THREAT,RESEARCH,DESIGN,IMPLEMENT develop
    class TEST,TUNE test
    class DEPLOY,MONITOR,MAINTAIN prod
    class VALIDATE,FP_CHECK,FEEDBACK decision
```

---

## Detection Coverage by MITRE ATT&CK

### Tactics Covered (11/14)
```
✅ Initial Access (T1078, T1110)
✅ Execution (T1059)
✅ Persistence (T1053, T1543, T1547)
✅ Privilege Escalation (T1548, T1078)
✅ Defense Evasion (T1027, T1070, T1553, T1562)
✅ Credential Access (T1003, T1552, T1555, T1558)
✅ Discovery (T1046, T1018, T1082, T1087)
✅ Lateral Movement (T1021)
✅ Collection (T1005, T1113, T1560)
✅ Command & Control (T1071, T1095, T1572)
✅ Exfiltration (T1041, T1048, T1567)

⬜ Impact (not covered — intentional)
⬜ Reconnaissance (limited coverage)
⬜ Resource Development (limited coverage)
```

### Techniques Covered (466+)

*Custom rules map 45+ unique techniques. SOCFortress community rules add 400+ more.*

Key techniques with dedicated detection:
- T1110: Brute Force
- T1059.001: PowerShell
- T1548.003: Sudo/Sudo Caching
- T1003: OS Credential Dumping (3 sub-techniques)
- T1021: Remote Services (5 sub-techniques)
- T1048: Exfiltration Over Alternative Protocol
- T1071: Application Layer Protocol (C2)
- T1543: Create or Modify System Process (4 sub-techniques)
- T1555: Credentials from Password Stores (Keychain, browsers)
- T1553.001: Gatekeeper Bypass (macOS)
- And 400+ more via SOCFortress community rules

---

## Continuous Improvement

### Feedback Loop
```mermaid
graph LR
    DETECT[Detection] --> RESPOND[Response]
    RESPOND --> ANALYZE[Analysis]
    ANALYZE --> LEARN[Lessons Learned]
    LEARN --> IMPROVE[Improve Rules]
    IMPROVE --> DETECT
    
    classDef cycle fill:#3B48CC,stroke:#232F3E,stroke-width:2px,color:#fff
    class DETECT,RESPOND,ANALYZE,LEARN,IMPROVE cycle
```

### Improvement Sources
1. **Incident Analysis**: Learn from real incidents
2. **Threat Intelligence**: New attack techniques
3. **False Positives**: Tune rules to reduce noise
4. **False Negatives**: Add missing detections
5. **Attack Simulations**: Validate coverage
6. **Industry Research**: Security publications

---

**Diagram Type**: Detection Pipeline  
**Last Updated**: 2026-02-15  
**Version**: 2.0
