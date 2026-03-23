# AI-Powered Alert Analyst

## 🤖 Overview

The AI Alert Analyst is an intelligent security assistant that enhances Wazuh alerts with:
- **Meaningful Alert Names** - Human-readable titles instead of rule IDs
- **Context Gathering** - Automatic enrichment with related events
- **AI-Generated Summaries** - Clear explanations of what happened
- **Actionable Next Steps** - Recommendations aligned with IR playbooks
- **Severity Assessment** - AI-assisted priority determination

### 🧠 Anomaly Detection Agent

The **AI Anomaly Detector** is a proactive companion to the alert analyst that catches threats signature-based rules miss:

- **Behavioral Baselines** - Builds per-agent/user norms from historical events
- **Statistical Deviation Detection** - Flags activity that deviates from baselines using z-scores
- **AI-Powered Reasoning** - LLM analyzes flagged anomalies for true/false positive assessment
- **MITRE ATT&CK Mapping** - Maps behavioral anomalies to known attack techniques

| | Alert Analyst | Anomaly Detector |
|---|---|---|
| **Trigger** | Reactive — after a rule fires | Proactive — scheduled scans |
| **Input** | Single alert | Batch of events |
| **Detection** | Enriches known signatures | Finds novel behaviors |

## 🎯 Features

### Alert Enrichment
- Gathers related events from the same source IP/user
- Correlates with historical alerts
- Adds threat intelligence context
- Maps to MITRE ATT&CK techniques

### AI Analysis
- Generates meaningful alert titles
- Provides executive-friendly summaries
- Recommends specific investigation steps
- Suggests containment actions
- Links to relevant playbooks

### Anomaly Detection Categories
- **Login Anomalies** — Unusual hours, impossible travel, new source IPs
- **Process Anomalies** — New/unknown processes on monitored hosts
- **Privilege Anomalies** — Unusual sudo usage, new privileged commands
- **Network Anomalies** — Traffic from unknown IPs, volume spikes
- **File Integrity Anomalies** — Sudden bursts of file changes
- **Volume Anomalies** — Event rate spikes indicating active attacks

### Integration
- Real-time alert processing
- Batch analysis mode
- REST API for integration
- CLI tool for manual analysis

## 🚀 Quick Start

### Prerequisites

```bash
# Python 3.9+
python3 --version

# Install dependencies
pip install -r requirements.txt

# Set API key (choose one)
export OPENAI_API_KEY="your-key"
# OR
export ANTHROPIC_API_KEY="your-key"
# OR use local Ollama (no API key needed)

# Required for live Wazuh mode
export WAZUH_PASSWORD="your-wazuh-api-password"

# Required if you use RAG/OpenSearch
export OPENSEARCH_USER="your-opensearch-user"
export OPENSEARCH_PASSWORD="your-opensearch-password"

# Required for API server auth (enabled by default)
export AI_ANALYST_API_TOKEN="long-random-token"
```

### Alert Analysis

```bash
# Analyze a single alert
python src/analyze_alert.py --alert-id 200001

# Analyze recent alerts
python src/analyze_alert.py --recent 10

# Monitor alerts in real-time
python src/analyze_alert.py --monitor

# Generate incident report
python src/analyze_alert.py --alert-id 200001 --report

# Write report to file
python src/analyze_alert.py --alert-id 200001 --report /tmp/incident-report.md

# Run in explicit demo mode (mock fallbacks allowed)
python src/analyze_alert.py --demo --mode demo
```

### Anomaly Detection

```bash
# Run with mock data (no live Wazuh needed)
python src/detect_anomalies.py --demo

# Analyze last 24 hours from live Wazuh
python src/detect_anomalies.py --hours 24

# Continuous monitoring (scans every 5 minutes)
python src/detect_anomalies.py --monitor --interval 300

# Output as JSON for pipeline integration
python src/detect_anomalies.py --demo --format json

# Adjust sensitivity (lower threshold = more alerts)
python src/detect_anomalies.py --demo --threshold 2.0

# Use config-defined defaults (lookback/interval/threshold/categories)
python src/detect_anomalies.py --config config/settings.yaml
```

### Example Alert Analysis Output

```
╔══════════════════════════════════════════════════════════════════╗
║                    AI ALERT ANALYSIS                             ║
╚══════════════════════════════════════════════════════════════════╝

📋 ALERT: Targeted SSH Brute Force Against Root Account
   Rule: 200001 | Severity: HIGH | Time: 2026-01-28 14:32:15 UTC

🎯 SUMMARY:
   An automated SSH brute force attack was detected targeting the 
   root account on server linux-endpoint-01. The attack originated 
   from IP 203.0.113.45 (located in Country X, ASN: AS12345) and 
   consisted of 47 failed login attempts over 3 minutes. The IP has 
   been previously reported for malicious SSH scanning activity.

📊 CONTEXT:
   • Source IP: 203.0.113.45 (First seen: 2026-01-28, Reports: 127)
   • Target: linux-endpoint-01 (10.0.2.155)
   • Targeted User: root
   • Attack Duration: 3 minutes (14:29:00 - 14:32:15)
   • Total Attempts: 47 failed logins
   • Attack Pattern: Credential stuffing (common password list)
   • Threat Intel: IP flagged in AbuseIPDB (Confidence: 95%)

🔍 INVESTIGATION STEPS:
   1. Verify no successful logins from 203.0.113.45
   2. Check for other systems targeted by this IP
   3. Review authentication logs for targeted user
   4. Assess current access to root account

🛡️ RECOMMENDED ACTIONS:
   1. [IMMEDIATE] Block IP 203.0.113.45 at firewall
   2. [IMMEDIATE] Verify root account is not compromised
   3. [SHORT-TERM] Enable fail2ban if not already active
   4. [LONG-TERM] Disable root SSH login, use sudo instead

📖 PLAYBOOK: SSH Brute Force Response (IR-PB-001)
   Link: incident-response/playbooks/ssh-brute-force.md

🏷️ MITRE ATT&CK: T1110.001 - Brute Force: Password Guessing
```

## 📁 Project Structure

```
ai-analyst/
├── README.md                    # This file
├── ai-analyze.sh                # Wazuh active-response entrypoint
├── requirements.txt             # Python dependencies
├── config/
│   └── settings.yaml            # Runtime and security configuration
├── prompts/
│   ├── analyze_alert.txt        # Alert analysis prompt
│   └── anomaly_analysis.txt     # Anomaly detection prompt
├── src/
│   ├── analyze_alert.py         # Alert analyst CLI
│   ├── detect_anomalies.py      # Anomaly detector CLI
│   ├── api_server.py            # REST API server
│   ├── anomaly_detector.py      # Anomaly detection engine
│   ├── baseline_engine.py       # Behavioral baseline builder
│   ├── benchmark_rag.py         # Embedding/RAG latency benchmark
│   ├── prune_embedding_cache.py # Embedding cache pruning utility
│   ├── alert_enricher.py        # Context gathering
│   ├── ai_client.py             # LLM integration
│   ├── wazuh_client.py          # Wazuh API client
│   ├── rag_retriever.py         # RAG context retrieval
│   └── config_loader.py         # Settings loader + security checks
├── baselines/                   # Persisted agent baselines (auto-created)
└── examples/
    ├── sample_alert.json        # Example alert for testing
    └── sample_output.md         # Example analysis output
```

## ⚙️ Configuration

### settings.yaml

```yaml
runtime:
  mode: "strict"  # strict or demo

ai:
  provider: "openai"  # openai, anthropic, ollama, mock
  openai_model: "gpt-4"
  temperature: 0.3
  max_tokens: 2000

# Wazuh Configuration
wazuh:
  host: "localhost"
  port: 55000
  user: "wazuh-api"
  password_env: "WAZUH_PASSWORD"
  ssl_verify: true

# API (auth required by default)
api:
  host: "127.0.0.1"
  port: 8080
  require_auth: true
  auth_token_env: "AI_ANALYST_API_TOKEN"

# Anomaly Detection
anomaly_detection:
  lookback_hours: 24
  z_score_threshold: 2.5
  min_confidence: 0.6
  baseline_file: "baselines/agent_baselines.json"
  scan_interval_seconds: 300
  categories:
    login_anomalies: true
    network_anomalies: true
    process_anomalies: true
    privilege_anomalies: true
    file_integrity_anomalies: true
    volume_anomalies: true

rag:
  enabled: true
  embedding:
    cache_dir: "~/.cache/ai-analyst/embeddings"
    max_memory_entries: 5000
    max_disk_files: 50000
    max_disk_size_mb: 2048
    prune_interval_writes: 200
  opensearch:
    use_ssl: true
    verify_certs: true
    username_env: "OPENSEARCH_USER"
    password_env: "OPENSEARCH_PASSWORD"
  retrieval:
    hybrid_search: true
    text_weight: 0.3
    vector_weight: 0.7
    max_temporal_alerts: 10
    temporal_window_before: "2h"
    temporal_window_after: "2h"
    index_health_check: true
```

## ⚡ Performance & Cache

```bash
# Benchmark embedding + retrieval latency
python src/benchmark_rag.py --iterations 10 --output json

# Prune old/oversized embedding cache entries
python src/prune_embedding_cache.py --max-files 20000 --max-size-mb 1024 --max-age-days 30 --output json
```

## 🧠 How It Works

### Alert Analyst Pipeline
```
Wazuh Alert → Parse → Enrich Context → AI Analysis → Recommendations → Output
```

### Anomaly Detection Pipeline
```
Events → Aggregate Features → Compare to Baselines → Flag Deviations
    → AI Reasoning → Findings Report
```

## 🔌 API Integration

### REST API

```bash
# Start API server
python src/api_server.py

# Analyze alert via API
curl -X POST http://localhost:8080/analyze \
  -H "Authorization: Bearer $AI_ANALYST_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"alert_id": "200001"}'

# Health check
curl http://localhost:8080/health
```

### Wazuh Integration

Add to Wazuh's active response to auto-analyze alerts:

```xml
<command>
  <name>ai-analyze</name>
  <executable>ai-analyze.sh</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
  <command>ai-analyze</command>
  <location>server</location>
  <level>10</level>
</active-response>
```

Deploy helper script to Wazuh manager and run with least privilege:

```bash
# Copy script
scp ai-analyze.sh wazuh@<manager>:/var/ossec/active-response/bin/ai-analyze.sh

# Restrict permissions
ssh wazuh@<manager> "chmod 750 /var/ossec/active-response/bin/ai-analyze.sh"
```

## 📊 Supported Alert Types

| Alert Category | Rule IDs | Analysis Quality |
|----------------|----------|------------------|
| SSH Brute Force | 200001-200003 | ⭐⭐⭐⭐⭐ |
| PowerShell Abuse | 200010-200014 | ⭐⭐⭐⭐⭐ |
| Privilege Escalation | 200020-200022 | ⭐⭐⭐⭐ |
| Credential Dumping | 200070-200072 | ⭐⭐⭐⭐⭐ |
| Account Creation | 200030-200033 | ⭐⭐⭐⭐ |
| Persistence | 200060-200063 | ⭐⭐⭐⭐ |
| File Integrity | 200050-200053 | ⭐⭐⭐ |
| Defense Evasion | 200080-200082 | ⭐⭐⭐⭐ |

## 🎓 Resume Impact

**What to highlight:**
- "Developed AI-powered security alert analysis using LLMs"
- "Automated alert triage reducing analyst workload by 50%"
- "Integrated threat intelligence with AI summarization"
- "Built behavioral anomaly detection engine with statistical baselines"
- "Created proactive threat hunting agent using z-score deviation analysis"

**Example resume bullet:**
> *"Engineered AI-powered security analysis platform using GPT-4/Claude that enriches alerts with threat context, detects behavioral anomalies via statistical baselines, and provides MITRE ATT&CK-mapped findings with actionable response recommendations."*

## 📚 References

- [OpenAI API Documentation](https://platform.openai.com/docs)
- [Anthropic Claude API](https://docs.anthropic.com/)
- [Wazuh API Reference](https://documentation.wazuh.com/current/user-manual/api/reference.html)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

---

**Last Updated**: 2026-02-13  
**Version**: 2.0  
**Status**: Production-Ready
