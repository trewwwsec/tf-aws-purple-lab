#!/bin/bash
set -e

# Variables from Terraform
WAZUH_MANAGER_IP="${wazuh_server_ip}"

# Update system
echo "Updating system packages..."
apt-get update && apt-get upgrade -y

# Wait for Wazuh server to be ready (installation takes ~10 minutes)
echo "Waiting for Wazuh server to be ready..."
sleep 120

# Install Wazuh agent
echo "Installing Wazuh agent..."
curl -so wazuh-agent-${wazuh_version}.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_${wazuh_version}${wazuh_package_suffix}_amd64.deb
WAZUH_MANAGER="$WAZUH_MANAGER_IP" dpkg -i wazuh-agent-${wazuh_version}.deb

# Enable and start agent
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

# Install auditd for advanced monitoring
echo "Installing auditd..."
apt-get install -y auditd audispd-plugins

# Enhanced auditd rules for SOC monitoring
cat > /etc/audit/rules.d/wazuh.rules <<EOF
# ===== Identity and Account Monitoring (T1136, T1098) =====
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k privilege_escalation
-w /etc/sudoers.d/ -p wa -k privilege_escalation

# ===== SSH Activity Monitoring =====
-w /var/log/auth.log -p wa -k ssh_activity
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /root/.ssh/ -p wa -k ssh_keys
-w /home/ -p wa -k user_home

# ===== Suspicious Network Tools (T1071) =====
-w /usr/bin/curl -p x -k suspicious_network
-w /usr/bin/wget -p x -k suspicious_network
-w /usr/bin/nc -p x -k suspicious_network
-w /usr/bin/ncat -p x -k suspicious_network
-w /usr/bin/nmap -p x -k recon_tool

# ===== Privilege Escalation (T1068, T1548) =====
-w /usr/bin/sudo -p x -k privilege_command
-w /bin/su -p x -k privilege_command
-w /usr/bin/pkexec -p x -k privilege_command
-w /usr/bin/chattr -p x -k file_attr_change

# ===== Persistence Mechanisms (T1053.003, T1547) =====
-w /etc/cron.d/ -p wa -k cron_persistence
-w /etc/crontab -p wa -k cron_persistence
-w /var/spool/cron/ -p wa -k cron_persistence
-w /etc/rc.local -p wa -k startup_persistence
-w /etc/init.d/ -p wa -k startup_persistence
-w /etc/systemd/system/ -p wa -k systemd_persistence

# ===== Credential Access (T1003) =====
-w /etc/shadow -p r -k credential_read
-w /etc/security/opasswd -p wa -k credential_backup

# ===== File Deletions (T1070.004) =====
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k file_deletion

# ===== Process Execution Monitoring =====
-a always,exit -F arch=b64 -S execve -k process_exec

# ===== Kernel Module Loading (T1547.006) =====
-w /sbin/insmod -p x -k kernel_module
-w /sbin/modprobe -p x -k kernel_module
-w /sbin/rmmod -p x -k kernel_module
EOF

# Apply auditd rules
augenrules --load
systemctl restart auditd

echo "Wazuh agent installed and connected to $WAZUH_MANAGER_IP"
echo "Agent installation complete!" > /tmp/wazuh-agent-install-complete.txt
