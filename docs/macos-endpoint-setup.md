# macOS Endpoint Setup

This guide covers how to add macOS endpoints to your Cloud SOC Platform for monitoring.

## 📋 Options

| Option | Cost | Best For | Setup Time |
|--------|------|----------|------------|
| **Local Mac** | Free | Testing, development | 5 minutes |
| **AWS EC2 Mac** | ~$26/day | Production demos | 25 minutes |

---

## 🖥️ Option 1: Use Your Local Mac (Recommended)

The easiest way to test macOS detection is to install the Wazuh agent on your local Mac.

### Prerequisites

- macOS 11+ (Big Sur, Monterey, Ventura, or Sonoma)
- Admin privileges (sudo access)
- Wazuh server deployed and accessible
- Network connectivity to Wazuh server on ports 1514, 1515

### Quick Setup

```bash
# Get your Wazuh server IP
cd terraform
WAZUH_IP=$(terraform output -raw wazuh_public_ip)

# Run the setup script
cd ..
./scripts/setup-local-mac-agent.sh $WAZUH_IP
```

### Manual Setup

If you prefer manual installation:

```bash
# 1. Download Wazuh agent
curl -o wazuh-agent.pkg https://packages.wazuh.com/4.x/macos/wazuh-agent-4.7.0-1.pkg

# 2. Install (requires sudo)
sudo installer -pkg wazuh-agent.pkg -target /

# 3. Register with Wazuh manager
sudo /Library/Ossec/bin/agent-auth -m <WAZUH_SERVER_IP> -A "my-mac"

# 4. Update server address
sudo sed -i '' "s|<address>.*</address>|<address><WAZUH_SERVER_IP></address>|g" /Library/Ossec/etc/ossec.conf

# 5. Start the agent
sudo /Library/Ossec/bin/wazuh-control start

# 6. Verify
sudo /Library/Ossec/bin/wazuh-control status
```

### Verify Connection

```bash
# Check agent status
sudo /Library/Ossec/bin/wazuh-control status

# View agent ID and key
sudo cat /Library/Ossec/etc/client.keys

# Check logs for errors
tail -f /Library/Ossec/logs/ossec.log
```

In the Wazuh dashboard:
1. Navigate to **Agents** → **Endpoints Summary**
2. Your Mac should appear as connected

---

## ☁️ Option 2: AWS EC2 Mac Instance

⚠️ **COST WARNING**: AWS macOS instances require Dedicated Hosts at ~$1.083/hour (~$26/day, ~$780/month).

### Why So Expensive?

Apple's licensing requires macOS to run on Apple hardware. AWS provides Dedicated Hosts with actual Mac mini hardware, which is expensive to maintain.

### When to Use This

- Production demos for clients/interviews
- Testing enterprise macOS deployments
- Compliance validation requiring cloud infrastructure

### Enable macOS in Terraform

1. **Edit the Terraform configuration:**

```bash
cd terraform
code macos_endpoint.tf  # Uncomment all resources
```

2. **Uncomment all resources in `macos_endpoint.tf`**

3. **Deploy:**

```bash
terraform init
terraform plan   # Review the cost implications!
terraform apply
```

4. **Wait ~25 minutes for:**
   - Dedicated Host allocation (10-15 min)
   - macOS instance boot (10-15 min)

5. **Connect via SSH:**

```bash
# Through bastion/Wazuh server (macOS is in private subnet)
ssh -J ubuntu@<WAZUH_IP> ec2-user@<MACOS_PRIVATE_IP>
```

### DESTROY WHEN DONE!

```bash
# Avoid $26/day charges
terraform destroy -target=aws_instance.macos_endpoint
terraform destroy -target=aws_ec2_host.macos_host
```

---

## 🧪 Testing macOS Detection

Once your agent is connected, run the attack simulations:

```bash
# On your Mac (local or EC2)
cd attack-simulation
./macos-attacks.sh
```

### Expected Alerts

| Test | Rule ID | Description |
|------|---------|-------------|
| Launch Agent | 200200 | Persistence mechanism |
| osascript | 200210 | AppleScript execution |
| Keychain | 200220 | Credential access |
| Gatekeeper | 200230 | Defense evasion |
| Screen capture | 200250 | Collection technique |

---

## 🔧 Troubleshooting

### Agent Won't Start

```bash
# Check logs
sudo tail -50 /Library/Ossec/logs/ossec.log

# Restart agent
sudo /Library/Ossec/bin/wazuh-control restart
```

### Registration Failed

```bash
# On Wazuh server, manually add agent
sudo /var/ossec/bin/manage_agents -a

# Then import key on Mac
sudo /Library/Ossec/bin/manage_agents -i <KEY>
```

### No Alerts Appearing

1. Verify agent shows as "Active" in Wazuh dashboard
2. Check that macOS rules are deployed:
   ```bash
   # On Wazuh server
   ls -la /var/ossec/etc/rules/macos_rules.xml
   ```
3. Restart Wazuh manager after adding rules:
   ```bash
   sudo systemctl restart wazuh-manager
   ```

### Network Issues

```bash
# Test connectivity to Wazuh server
telnet <WAZUH_IP> 1514
telnet <WAZUH_IP> 1515

# Check firewall
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --listapps
```

---

## 📊 macOS-Specific Monitoring

The Wazuh agent monitors these macOS-specific paths:

| Path | Purpose |
|------|---------|
| `~/Library/LaunchAgents/` | User-level persistence |
| `/Library/LaunchAgents/` | System-level persistence (user) |
| `/Library/LaunchDaemons/` | System-level persistence (root) |
| `~/.ssh/` | SSH keys and config |
| `/etc/periodic/` | Scheduled scripts |
| `/usr/local/bin/` | Third-party executables |

---

## 📚 Additional Resources

- [Wazuh macOS Documentation](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/macos.html)
- [macOS Security Overview (Apple)](https://support.apple.com/guide/security/)
- [MITRE ATT&CK for macOS](https://attack.mitre.org/matrices/enterprise/macos/)
- [Objective-See Tools](https://objective-see.org/tools.html)

---

**Last Updated**: 2026-01-28
