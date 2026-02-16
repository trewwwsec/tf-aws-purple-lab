# High-Level Architecture

## Cloud SOC Platform - System Overview

This diagram shows the complete Cloud SOC Platform architecture including infrastructure, detection, and incident response components.

```mermaid
graph TB
    subgraph "AWS Cloud - VPC 10.0.0.0/16"
        subgraph "Public Subnet - 10.0.1.0/24"
            IGW[Internet Gateway]
            WAZUH[Wazuh SIEM Server<br/>t3.medium<br/>Ubuntu 22.04]
        end
        
        subgraph "Private Subnet - 10.0.2.0/24"
            LINUX[Linux Endpoint<br/>t3.micro<br/>Ubuntu 22.04]
            WINDOWS[Windows Endpoint<br/>t3.micro<br/>Windows Server 2022]
            NAT[NAT Gateway]
        end
        
        subgraph "Security"
            SG1[Security Group<br/>Wazuh Server]
            SG2[Security Group<br/>Endpoints]
        end
    end
    
    subgraph "External Access"
        ANALYST[SOC Analyst]
        ATTACKER[Simulated Attacker]
    end
    
    subgraph "Detection & Response"
        RULES[2,226+ Detection Rules<br/>MITRE ATT&CK Mapped]
        AI_ANALYST[AI Alert Analyst<br/>LLM-Powered Triage]
        ANOMALY[Anomaly Detector<br/>Statistical Baselines]
        ALERTS[Alert Generation<br/>SIEM Dashboard]
        PLAYBOOKS[Incident Response<br/>Playbooks]
    end
    
    subgraph "Testing & Validation"
        APT_SIM[APT29 Kill Chain<br/>Multi-Victim Orchestrator]
        SIMULATIONS[Attack Simulations<br/>30+ Scenarios]
        EVIDENCE[Evidence Collection<br/>Forensic Tools]
    end
    
    %% Connections
    IGW --> WAZUH
    ANALYST --> IGW
    ATTACKER -.->|Simulated Attacks| IGW
    
    WAZUH --> NAT
    NAT --> LINUX
    NAT --> WINDOWS
    
    LINUX -->|Logs & Events| WAZUH
    WINDOWS -->|Logs & Events| WAZUH
    
    WAZUH --> RULES
    RULES --> ALERTS
    ALERTS --> AI_ANALYST
    AI_ANALYST --> ANOMALY
    ALERTS --> PLAYBOOKS
    
    APT_SIM -.->|Deploy & Execute| LINUX
    APT_SIM -.->|Deploy & Execute| WINDOWS
    SIMULATIONS -.->|Test Detections| LINUX
    SIMULATIONS -.->|Test Detections| WINDOWS
    PLAYBOOKS --> EVIDENCE
    
    SG1 -.->|Protects| WAZUH
    SG2 -.->|Protects| LINUX
    SG2 -.->|Protects| WINDOWS
    
    %% Styling
    classDef aws fill:#FF9900,stroke:#232F3E,stroke-width:2px,color:#fff
    classDef server fill:#3B48CC,stroke:#232F3E,stroke-width:2px,color:#fff
    classDef security fill:#DD344C,stroke:#232F3E,stroke-width:2px,color:#fff
    classDef detection fill:#1E8900,stroke:#232F3E,stroke-width:2px,color:#fff
    classDef external fill:#666,stroke:#232F3E,stroke-width:2px,color:#fff
    
    class IGW,NAT aws
    class WAZUH,LINUX,WINDOWS server
    class SG1,SG2 security
    class RULES,ALERTS,PLAYBOOKS,AI_ANALYST,ANOMALY,SIMULATIONS,APT_SIM,EVIDENCE detection
    class ANALYST,ATTACKER external
```

## Component Details

### Infrastructure Layer
- **AWS VPC**: Isolated network environment (10.0.0.0/16)
- **Public Subnet**: Internet-accessible resources (Wazuh server)
- **Private Subnet**: Protected endpoints (monitored systems)
- **Internet Gateway**: External connectivity
- **NAT Gateway**: Outbound internet for private subnet

### SIEM Layer
- **Wazuh Server**: Central SIEM and log aggregation
  - Receives logs from all endpoints
  - Processes events through detection rules
  - Generates alerts for security incidents
  - Provides web dashboard for analysts

### Endpoint Layer
- **Linux Endpoint**: Ubuntu 22.04 with Wazuh agent
  - Monitors system logs, authentication, file integrity
  - Sends events to Wazuh server
  - Target for attack simulations
  
- **Windows Endpoint**: Windows Server 2022 with Wazuh agent
  - Monitors PowerShell, event logs, registry
  - Sends events to Wazuh server
  - Target for PowerShell attack simulations

### Detection Layer
- **2,226+ Detection Rules**: 82 custom + 2,144 SOCFortress community rules
  - SSH brute force (T1110)
  - PowerShell abuse (T1059.001)
  - Privilege escalation (T1548.003)
  - Credential dumping (T1003)
  - Lateral movement (T1021)
  - Persistence mechanisms (T1053, T1543)
  - Data exfiltration (T1048, T1567)
  - macOS-specific detections (32 rules)
  - 466+ MITRE ATT&CK techniques mapped

### AI & Analytics Layer
- **AI Alert Analyst**: LLM-powered alert triage (OpenAI, Anthropic, Ollama)
  - Context-aware summaries and investigation steps
  - Automatic playbook linking
  - Threat intelligence enrichment
- **Anomaly Detection Engine**: Statistical baseline analysis
  - Login pattern anomalies
  - C2 beaconing detection
  - DNS exfiltration detection
  - Process behavior profiling

### Response Layer
- **Incident Response Playbooks**:
  - SSH Brute Force (IR-PB-001)
  - Credential Dumping (IR-PB-002)
  - PowerShell Abuse (IR-PB-003)
  - Privilege Escalation (IR-PB-004)
  - Persistence (IR-PB-005)
  - macOS Compromise (IR-PB-006)
  - Complete NIST SP 800-61r2 lifecycle
  - Evidence collection tools

### Testing Layer
- **APT29 Kill Chain Orchestrator**: Multi-victim deployment via SSH/SCP
  - Deploys and executes 30+ attack techniques
  - Cross-platform: Linux, macOS, Windows
  - 6-phase kill chain (deploy → discovery → credential → C2 → priv esc → cleanup)
- **Attack Simulations**: Individual technique scripts
  - Credential harvesting (8 scenarios)
  - Lateral movement (7 scenarios)
  - C2 and exfiltration (7 scenarios)
  - Validates detection effectiveness

## Data Flow

1. **Log Collection**: Endpoints send logs to Wazuh server
2. **Event Processing**: Wazuh processes logs through detection rules
3. **Alert Generation**: Matching events trigger alerts
4. **Incident Response**: Analysts follow playbooks
5. **Evidence Collection**: Forensic tools gather evidence
6. **Continuous Improvement**: Lessons learned update detections

## Security Controls

- **Network Segmentation**: Public/private subnet separation
- **Security Groups**: Firewall rules limiting access
- **Least Privilege**: Minimal required permissions
- **Encryption**: TLS for all communications
- **Monitoring**: 24/7 SIEM monitoring
- **Incident Response**: Documented procedures

## Scalability

- **Horizontal**: Add more endpoints as needed
- **Vertical**: Upgrade Wazuh server instance size
- **Multi-Region**: Deploy in multiple AWS regions
- **High Availability**: Add redundant Wazuh servers

## Compliance

- **PCI DSS**: Log monitoring, access control
- **NIST**: Incident response framework
- **GDPR**: Data protection, breach notification
- **HIPAA**: Audit logging, access controls

---

**Diagram Type**: High-Level Architecture  
**Last Updated**: 2026-02-15  
**Version**: 2.0
