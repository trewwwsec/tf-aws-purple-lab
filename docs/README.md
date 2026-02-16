# Documentation

Project documentation for the Cloud SOC Platform.

## Contents

### Architecture & Diagrams

| Document | Description |
|----------|-------------|
| [High-Level Architecture](diagrams/01-high-level-architecture.md) | System architecture — AWS infra, SIEM, AI analyst, APT simulation |
| [Network Architecture](diagrams/02-network-architecture.md) | VPC topology, subnets, NAT, security groups |
| [Incident Response Workflow](diagrams/04-incident-response-workflow.md) | NIST SP 800-61r2 IR process flow |
| [Detection Pipeline](diagrams/05-detection-pipeline.md) | End-to-end detection flow (2,226+ rules, AI anomaly detection) |

### Coverage & Demos

| Document | Description |
|----------|-------------|
| [MITRE ATT&CK Coverage](MITRE_COVERAGE.md) | Full coverage matrix — 466+ techniques, 11 tactics |
| [APT Simulation Demo](APT-SIMULATION-DEMO.md) | Live Wazuh screenshots from APT29 kill chain execution |
| [Demo Screenshots](demo-screenshots/) | Real Wazuh dashboard captures |

### Setup Guides

| Document | Description |
|----------|-------------|
| [macOS Endpoint Setup](macos-endpoint-setup.md) | Agent installation on macOS (local & EC2 Mac) |

## Related Documentation

Each component directory has its own README with deployment and usage details:

- [`detections/README.md`](../detections/README.md) — Detection rules deployment, tuning, and compliance mapping
- [`attack-simulation/README.md`](../attack-simulation/README.md) — Attack scripts and APT29 kill chain
- [`incident-response/README.md`](../incident-response/README.md) — IR playbooks and escalation procedures
- [`ai-analyst/README.md`](../ai-analyst/README.md) — AI alert analyst and anomaly detection engine

---

**Last Updated**: 2026-02-15
