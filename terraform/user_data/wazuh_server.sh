#!/bin/bash
set -e

# Update system
echo "Updating system packages..."
apt-get update && apt-get upgrade -y

# Install prerequisites
apt-get install -y curl tar

# Download Wazuh installation script
echo "Downloading Wazuh installation script..."
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.7/config.yml

# Run Wazuh all-in-one installation
echo "Installing Wazuh (this takes ~10 minutes)..."
bash wazuh-install.sh --all-in-one -i

# Save credentials
echo "Saving installation files..."
tar -xvf wazuh-install-files.tar

# Enable and start services
systemctl enable wazuh-manager
systemctl start wazuh-manager

%{ if enable_cloudtrail_wazuh_ingestion }
# Configure Wazuh AWS module for CloudTrail management event ingestion.
echo "Configuring Wazuh CloudTrail ingestion from S3..."
cat > /tmp/wazuh-cloudtrail-wodle.xml << 'WAZUHAWS'
  <!-- Managed by Terraform: CloudTrail -> S3 -> Wazuh aws-s3 ingestion -->
  <wodle name="aws-s3">
    <disabled>no</disabled>
    <interval>10m</interval>
    <run_on_start>yes</run_on_start>
    <skip_on_error>yes</skip_on_error>
    <bucket type="cloudtrail">
      <name>${cloudtrail_bucket_name}</name>
%{ if cloudtrail_regions != "" }
      <regions>${cloudtrail_regions}</regions>
%{ endif }
      <remove_from_bucket>no</remove_from_bucket>
    </bucket>
  </wodle>
WAZUHAWS

python3 << 'PYCONF'
from pathlib import Path

ossec_conf = Path('/var/ossec/etc/ossec.conf')
wodle = Path('/tmp/wazuh-cloudtrail-wodle.xml').read_text().rstrip()
config = ossec_conf.read_text()
start = '  <!-- BEGIN TERRAFORM MANAGED CLOUDTRAIL WAZUH INGESTION -->'
end = '  <!-- END TERRAFORM MANAGED CLOUDTRAIL WAZUH INGESTION -->'
managed = f"{start}\n{wodle}\n{end}"

if start in config and end in config:
    before, rest = config.split(start, 1)
    _, after = rest.split(end, 1)
    config = before + managed + after
else:
    closing = '</ossec_config>'
    if closing not in config:
        raise SystemExit(f'{ossec_conf} does not contain {closing}')
    config = config.replace(closing, managed + '\n' + closing, 1)

ossec_conf.write_text(config)
PYCONF

chown root:wazuh /var/ossec/etc/ossec.conf
chmod 640 /var/ossec/etc/ossec.conf
systemctl restart wazuh-manager
echo "CloudTrail ingestion configured for bucket ${cloudtrail_bucket_name}"
%{ endif }

# Configure centralized agent configuration (Phase 3 & 4)
echo "Configuring centralized agent settings..."
cat > /var/ossec/etc/shared/default/agent.conf << 'AGENTCONF'
<agent_config os="linux">
  <!-- File Integrity Monitoring for Linux -->
  <syscheck>
    <directories check_all="yes" realtime="yes">/etc,/bin,/sbin,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes" report_changes="yes">/home</directories>
    <directories check_all="yes">/root</directories>
    <directories check_all="yes">/var/www</directories>
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/adjtime</ignore>
    <frequency>300</frequency>
  </syscheck>
  
  <!-- Log Collection for Linux -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>
  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/secure</location>
  </localfile>
</agent_config>

<agent_config os="windows">
  <!-- File Integrity Monitoring for Windows -->
  <syscheck>
    <directories check_all="yes" realtime="yes">C:\Windows\System32</directories>
    <directories check_all="yes">C:\Program Files</directories>
    <directories check_all="yes" report_changes="yes">C:\Users</directories>
    <directories check_all="yes">C:\Windows\System32\config</directories>
    <ignore type="sregex">.log$</ignore>
    <frequency>300</frequency>
  </syscheck>
  
  <!-- Windows Event Log Collection -->
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
    <query>Event/System[EventID != 5145 and EventID != 5156 and EventID != 4688]</query>
  </localfile>
  <localfile>
    <location>System</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>Application</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</agent_config>

<agent_config os="macos">
  <!-- File Integrity Monitoring for macOS -->
  <syscheck>
    <directories check_all="yes" realtime="yes">~/Library/LaunchAgents</directories>
    <directories check_all="yes" realtime="yes">/Library/LaunchAgents</directories>
    <directories check_all="yes" realtime="yes">/Library/LaunchDaemons</directories>
    <directories check_all="yes">~/.ssh</directories>
    <directories check_all="yes">/etc/periodic</directories>
    <directories check_all="yes">/usr/local/bin</directories>
    <directories check_all="yes">/Applications</directories>
    <ignore>/Library/Logs</ignore>
    <ignore>~/.Trash</ignore>
    <ignore>/private/var/log</ignore>
    <frequency>300</frequency>
  </syscheck>
  
  <!-- macOS System Log Collection -->
  <localfile>
    <log_format>macos</log_format>
    <location>macos</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/system.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/install.log</location>
  </localfile>
</agent_config>
AGENTCONF

echo "Agent configuration deployed to /var/ossec/etc/shared/default/agent.conf"

# Install CloudWatch agent (optional for monitoring)
echo "Installing CloudWatch agent..."
wget -q https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
dpkg -i amazon-cloudwatch-agent.deb

# Create completion marker
echo "Wazuh installation complete!" > /tmp/wazuh-install-complete.txt

# Get public IP for display
PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)

# Log system info
echo "===================================" >> /var/log/wazuh-install.log
echo "Wazuh Installation Complete" >> /var/log/wazuh-install.log
echo "Timestamp: $(date)" >> /var/log/wazuh-install.log
echo "Public IP: $PUBLIC_IP" >> /var/log/wazuh-install.log
echo "Dashboard URL: https://$PUBLIC_IP" >> /var/log/wazuh-install.log
echo "Credentials file: /home/ubuntu/wazuh-install-files.tar" >> /var/log/wazuh-install.log
echo "" >> /var/log/wazuh-install.log
echo "Agent Configurations:" >> /var/log/wazuh-install.log
echo "  - Linux, Windows, macOS agents supported" >> /var/log/wazuh-install.log
echo "===================================" >> /var/log/wazuh-install.log

echo ""
echo "======================================================================"
echo "           WAZUH INSTALLATION COMPLETE                                "
echo "======================================================================"
echo ""
echo "Dashboard URL: https://$PUBLIC_IP"
echo ""
echo "To get credentials:"
echo "  sudo tar -xvf wazuh-install-files.tar"
echo "  sudo cat wazuh-install-files/wazuh-passwords.txt"
echo ""
echo "NOTE: Custom detection rules will be deployed via Terraform provisioner"
echo ""
