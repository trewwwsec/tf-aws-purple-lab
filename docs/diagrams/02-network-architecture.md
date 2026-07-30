# Network Architecture

## AWS VPC Network Topology

This diagram shows the detailed network architecture including subnets, routing, security groups, and network flows.

```mermaid
graph TB
    subgraph Internet
        USER[SOC Analyst<br/>203.0.113.0/24]
        THREAT[Threat Actors<br/>Internet]
    end
    
    subgraph "AWS Region: us-east-1"
        subgraph "VPC: purple-lab-vpc (10.0.0.0/16)"
            IGW[Internet Gateway<br/>igw-xxxxx]
            
            subgraph "Availability Zone: us-east-1a"
                subgraph "Public Subnet (10.0.1.0/24)"
                    WAZUH[Wazuh Server<br/>10.0.1.100<br/>Public IP: X.X.X.X]
                    NAT[NAT Gateway<br/>10.0.1.200<br/>Elastic IP]
                end
                
                subgraph "Private Subnet (10.0.2.0/24)"
                    LINUX[Linux Endpoint<br/>10.0.2.155<br/>No Public IP]
                    WINDOWS[Windows Endpoint<br/>10.0.2.156<br/>No Public IP]
                end
            end
            
            subgraph "Route Tables"
                RT_PUB[Public Route Table<br/>0.0.0.0/0 → IGW]
                RT_PRIV[Private Route Table<br/>0.0.0.0/0 → NAT]
            end
            
            subgraph "Security Groups"
                SG_WAZUH[SG: wazuh-server<br/>Inbound:<br/>22/tcp from 203.0.113.0/24<br/>443/tcp from 203.0.113.0/24<br/>1514/tcp from 10.0.2.0/24<br/>1515/tcp from 10.0.2.0/24]
                
                SG_ENDPOINTS[SG: endpoints<br/>Inbound:<br/>22/tcp from 10.0.1.0/24<br/>3389/tcp from 10.0.1.0/24<br/>Outbound:<br/>1514/tcp to 10.0.1.100<br/>1515/tcp to 10.0.1.100]
            end
            
            subgraph "Network ACLs"
                NACL_PUB[Public NACL<br/>Allow all inbound<br/>Allow all outbound]
                NACL_PRIV[Private NACL<br/>Allow from VPC<br/>Allow to VPC]
            end
        end
    end
    
    %% Network Flows
    USER -->|SSH/HTTPS| IGW
    THREAT -.->|Simulated Attacks| IGW
    IGW -->|Port 22, 443| WAZUH
    
    WAZUH -->|Management| NAT
    NAT -->|Internet Access| IGW
    
    LINUX -->|Logs: 1514/1515| WAZUH
    WINDOWS -->|Logs: 1514/1515| WAZUH
    
    NAT -->|Updates, Packages| LINUX
    NAT -->|Updates, Packages| WINDOWS
    
    %% Route Table Associations
    RT_PUB -.->|Associated| WAZUH
    RT_PUB -.->|Associated| NAT
    RT_PRIV -.->|Associated| LINUX
    RT_PRIV -.->|Associated| WINDOWS
    
    %% Security Group Associations
    SG_WAZUH -.->|Protects| WAZUH
    SG_ENDPOINTS -.->|Protects| LINUX
    SG_ENDPOINTS -.->|Protects| WINDOWS
    
    %% NACL Associations
    NACL_PUB -.->|Subnet Level| RT_PUB
    NACL_PRIV -.->|Subnet Level| RT_PRIV
    
    %% Styling
    classDef internet fill:#666,stroke:#333,stroke-width:2px,color:#fff
    classDef aws fill:#FF9900,stroke:#232F3E,stroke-width:2px,color:#fff
    classDef public fill:#3B48CC,stroke:#232F3E,stroke-width:2px,color:#fff
    classDef private fill:#1E8900,stroke:#232F3E,stroke-width:2px,color:#fff
    classDef security fill:#DD344C,stroke:#232F3E,stroke-width:2px,color:#fff
    classDef routing fill:#8C4FFF,stroke:#232F3E,stroke-width:2px,color:#fff
    
    class USER,THREAT internet
    class IGW,NAT aws
    class WAZUH public
    class LINUX,WINDOWS private
    class SG_WAZUH,SG_ENDPOINTS,NACL_PUB,NACL_PRIV security
    class RT_PUB,RT_PRIV routing
```

## Network Components

### VPC Configuration
- **CIDR Block**: 10.0.0.0/16 (65,536 IP addresses)
- **Region**: us-east-1
- **DNS Hostnames**: Enabled
- **DNS Resolution**: Enabled

### Subnets

#### Public Subnet (10.0.1.0/24)
- **Available IPs**: 251
- **Internet Access**: Direct via Internet Gateway
- **Resources**:
  - Wazuh SIEM Server (10.0.1.100)
  - NAT Gateway (10.0.1.200)
- **Use Case**: Internet-facing services

#### Private Subnet (10.0.2.0/24)
- **Available IPs**: 251
- **Internet Access**: Via NAT Gateway
- **Resources**:
  - Linux Endpoint (10.0.2.155)
  - Windows Endpoint (10.0.2.156)
- **Use Case**: Protected workloads

### Security Groups (Stateful Firewall)

#### Wazuh Server Security Group
```
Inbound Rules:
- SSH (22/tcp) from 203.0.113.0/24 (SOC analysts)
- HTTPS (443/tcp) from 203.0.113.0/24 (Web dashboard)
- Wazuh Agent (1514/tcp) from 10.0.2.0/24 (Log collection)
- Wazuh Registration (1515/tcp) from 10.0.2.0/24 (Agent registration)

Outbound Rules:
- All traffic allowed (default)
```

#### Endpoints Security Group
```
Inbound Rules:
- SSH (22/tcp) from 10.0.1.0/24 (Management from Wazuh subnet)
- RDP (3389/tcp) from 10.0.1.0/24 (Windows management)

Outbound Rules:
- Wazuh Agent (1514/tcp) to 10.0.1.100 (Send logs)
- Wazuh Registration (1515/tcp) to 10.0.1.100 (Agent registration)
- HTTPS (443/tcp) to 0.0.0.0/0 (Updates, packages)
```

### Routing

#### Public Route Table
```
Destination         Target
10.0.0.0/16        local (VPC)
0.0.0.0/0          igw-xxxxx (Internet Gateway)
```

#### Private Route Table
```
Destination         Target
10.0.0.0/16        local (VPC)
0.0.0.0/0          nat-xxxxx (NAT Gateway)
```

## Network Flows

### Log Collection Flow
```
Endpoint (10.0.2.x) → Wazuh Server (10.0.1.100:1514/1515)
```
- Wazuh agents send logs over TCP ports 1514/1515
- Encrypted communication using pre-shared keys
- Continuous real-time log streaming

### Management Access Flow
```
SOC Analyst (203.0.113.x) → Internet Gateway → Wazuh Server (10.0.1.100:443)
```
- HTTPS access to Wazuh web dashboard
- SSH access for server management
- Source IP restricted to analyst network

### Internet Access Flow (Endpoints)
```
Endpoint (10.0.2.x) → NAT Gateway (10.0.1.200) → Internet Gateway → Internet
```
- Endpoints access internet for updates
- NAT provides outbound-only connectivity
- No inbound connections from internet

### Attack Simulation Flow
```
Simulated Attacker → Internet Gateway → Wazuh Server (10.0.1.100:22)
```
- SSH brute force attacks for testing
- Controlled attack simulations
- Validates detection rules

## Security Layers

### Layer 1: Network ACLs (Stateless)
- Subnet-level filtering
- Allow/deny rules by IP and port
- Evaluated in order by rule number

### Layer 2: Security Groups (Stateful)
- Instance-level filtering
- Allow rules only (implicit deny)
- Automatic return traffic allowed

### Layer 3: Host Firewall
- OS-level firewall (iptables, Windows Firewall)
- Additional protection layer
- Configured via Terraform user_data

## High Availability Considerations

### Current Architecture
- Single Availability Zone (us-east-1a)
- Single Wazuh server
- Single NAT Gateway

### HA Improvements (Future)
```mermaid
graph LR
    subgraph "Multi-AZ Architecture"
        AZ1[AZ-1a<br/>Wazuh Primary<br/>NAT Gateway 1]
        AZ2[AZ-1b<br/>Wazuh Standby<br/>NAT Gateway 2]
        ELB[Application Load Balancer]
    end
    
    ELB --> AZ1
    ELB --> AZ2
```

## Network Monitoring

### VPC Flow Logs
- Capture IP traffic going to/from network interfaces
- Stored in CloudWatch Logs
- Used for security analysis and troubleshooting

### CloudWatch Metrics
- Network in/out
- NAT Gateway metrics
- VPC metrics

### Wazuh Network Monitoring
- Monitors network connections on endpoints
- Detects suspicious network activity
- Alerts on unusual traffic patterns

## Cost Optimization

### Current Costs (Estimated)
- **NAT Gateway**: ~$32/month (0.045/hour + data transfer)
- **Data Transfer**: ~$5/month (varies by usage)
- **Elastic IP**: Free (when associated with running instance)

### Cost Savings Options
- Use VPC endpoints for AWS services (avoid NAT charges)
- Implement VPC peering instead of internet routing
- Schedule non-production resources (stop when not in use)

## Compliance & Best Practices

✅ **Network Segmentation**: Public/private subnet separation  
✅ **Least Privilege**: Minimal security group rules  
✅ **Defense in Depth**: Multiple security layers (NACL + SG + Host)  
✅ **Encryption in Transit**: TLS for all communications  
✅ **Logging**: VPC Flow Logs enabled  
✅ **Monitoring**: CloudWatch + Wazuh SIEM  

---

**Diagram Type**: Network Architecture  
**Last Updated**: 2026-01-28  
**Version**: 1.0
