# Cloud SOC Platform - Architecture Diagrams

This directory contains architecture diagrams for the Cloud SOC Platform. All diagrams are created using Mermaid syntax, which renders automatically in GitHub, GitLab, and many documentation tools.

## 📊 Available Diagrams

1. **[High-Level Architecture](01-high-level-architecture.md)** — Overall system architecture with AI analyst and APT simulation layers
2. **[Network Architecture](02-network-architecture.md)** — AWS VPC topology (public/private subnets, NAT, security groups)
3. **[Incident Response Workflow](04-incident-response-workflow.md)** — NIST SP 800-61r2 IR process flow
4. **[Detection Pipeline](05-detection-pipeline.md)** — End-to-end detection flow (2,226+ rules, AI anomaly detection)

## 📸 Related Documentation

- **[APT Simulation Demo](../APT-SIMULATION-DEMO.md)** — Live Wazuh dashboard screenshots from real deployment
- **[MITRE ATT&CK Coverage](../MITRE_COVERAGE.md)** — Full coverage matrix (466+ techniques, 11 tactics)
- **[Demo Screenshots](../demo-screenshots/)** — Real Wazuh captures showing alerts and MITRE mapping

## 🎨 Viewing Diagrams

### On GitHub
Simply open any `.md` file - GitHub renders Mermaid diagrams automatically.

### Locally
Use a Mermaid-compatible viewer:
- **VS Code**: Install "Markdown Preview Mermaid Support" extension
- **Browser**: Use [Mermaid Live Editor](https://mermaid.live/)
- **CLI**: Use `mmdc` (mermaid-cli)

### Export to Images
```bash
# Install mermaid-cli
npm install -g @mermaid-js/mermaid-cli

# Convert to PNG
mmdc -i diagram.md -o diagram.png

# Convert to SVG
mmdc -i diagram.md -o diagram.svg
```

## 📝 Diagram Syntax

All diagrams use [Mermaid](https://mermaid.js.org/) syntax:
- **Flowcharts**: Process flows and workflows
- **Sequence Diagrams**: Interaction between components
- **Class Diagrams**: System components and relationships
- **State Diagrams**: System states and transitions
- **Network Diagrams**: Infrastructure topology

## 🎯 Use Cases

- **Portfolio**: Include in GitHub README and portfolio website
- **Documentation**: Technical documentation and runbooks
- **Presentations**: Export to images for slides
- **Training**: Onboarding new team members
- **Compliance**: Architecture documentation for audits

## 🔄 Updating Diagrams

1. Edit the Mermaid code in the `.md` file
2. Preview changes locally or on GitHub
3. Commit and push updates
4. Diagrams update automatically in documentation

---

**Last Updated**: 2026-02-15  
**Maintainer**: Cloud SOC Platform Team
