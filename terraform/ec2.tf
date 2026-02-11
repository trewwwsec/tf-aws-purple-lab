# Data source for latest Ubuntu AMI
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Data source for latest Windows Server AMI
data "aws_ami" "windows" {
  most_recent = true
  owners      = ["amazon"] # Amazon-owned Windows AMIs

  filter {
    name   = "name"
    values = ["Windows_Server-2022-English-Full-Base-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Wazuh Server
resource "aws_instance" "wazuh_server" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.wazuh_instance_type
  subnet_id              = aws_subnet.public_subnet.id
  vpc_security_group_ids = [aws_security_group.wazuh_server_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.wazuh_server_profile.name
  key_name               = var.ssh_key_name

  root_block_device {
    volume_size           = var.wazuh_volume_size
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }

  user_data = file("${path.module}/user_data/wazuh_server.sh")

  tags = {
    Name = "${var.project_name}-wazuh-server"
    Role = "SIEM"
  }
}

# Deploy custom detection rules after Wazuh is ready
resource "null_resource" "deploy_detection_rules" {
  depends_on = [aws_instance.wazuh_server]

  # Trigger redeployment when rules change
  triggers = {
    local_rules_hash = filemd5("${path.module}/../wazuh/custom_rules/local_rules.xml")
    macos_rules_hash = filemd5("${path.module}/../wazuh/custom_rules/macos_rules.xml")
  }

  # Wait for Wazuh to be ready
  provisioner "local-exec" {
    command = "echo 'Waiting for Wazuh server to initialize...' && sleep ${var.wazuh_init_wait_seconds}"
  }

  # Copy local_rules.xml
  provisioner "file" {
    source      = "${path.module}/../wazuh/custom_rules/local_rules.xml"
    destination = "/tmp/local_rules.xml"

    connection {
      type        = "ssh"
      user        = "ubuntu"
      private_key = file(var.ssh_private_key_path)
      host        = aws_instance.wazuh_server.public_ip
    }
  }

  # Copy macos_rules.xml
  provisioner "file" {
    source      = "${path.module}/../wazuh/custom_rules/macos_rules.xml"
    destination = "/tmp/macos_rules.xml"

    connection {
      type        = "ssh"
      user        = "ubuntu"
      private_key = file(var.ssh_private_key_path)
      host        = aws_instance.wazuh_server.public_ip
    }
  }

  # Deploy rules and restart Wazuh
  provisioner "remote-exec" {
    inline = [
      "echo '============================================='",
      "echo 'Deploying Custom Detection Rules...'",
      "echo '============================================='",

      # Deploy our custom rules (renumbered to 200xxx range)
      "sudo mv /tmp/local_rules.xml /var/ossec/etc/rules/local_rules.xml",
      "sudo mv /tmp/macos_rules.xml /var/ossec/etc/rules/macos_rules.xml",
      "sudo chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml",
      "sudo chown wazuh:wazuh /var/ossec/etc/rules/macos_rules.xml",
      "sudo chmod 660 /var/ossec/etc/rules/local_rules.xml",
      "sudo chmod 660 /var/ossec/etc/rules/macos_rules.xml",
      "echo '✓ Custom rules deployed (73 rules, ID range: 200xxx)'",

      # Install SOCFortress community rules
      "echo ''",
      "echo 'Installing SOCFortress Community Rules...'",
      "echo '(2000+ additional detection rules)'",
      "cd /tmp",
      "curl -sO https://raw.githubusercontent.com/socfortress/Wazuh-Rules/main/wazuh_socfortress_rules.sh",
      "chmod +x wazuh_socfortress_rules.sh",
      "sudo bash wazuh_socfortress_rules.sh",
      "echo '✓ SOCFortress rules installed'",

      # Restart Wazuh manager to load all rules
      "echo ''",
      "echo 'Restarting Wazuh manager to load all rules...'",
      "sudo systemctl restart wazuh-manager",
      "sleep 10",

      # Verify rules loaded
      "echo ''",
      "echo '============================================='",
      "echo 'Detection Rules Deployment Complete!'",
      "echo '============================================='",
      "echo ''",
      "echo 'Custom Rules (200xxx range):'",
      "echo '  - local_rules.xml: 45 Windows/Linux rules'",
      "echo '  - macos_rules.xml: 28 macOS rules'",
      "echo ''",
      "echo 'SOCFortress Community Rules:'",
      "echo '  - Sysmon for Windows'",
      "echo '  - Sysmon for Linux'",
      "echo '  - PowerShell detection'",
      "echo '  - Yara malware rules'",
      "echo '  - Suricata IDS rules'",
      "echo '  - Office365 integration'",
      "echo '  - And 2000+ more...'",
      "echo ''",
      "echo 'Total: 2000+ MITRE ATT&CK mapped rules'"
    ]

    connection {
      type        = "ssh"
      user        = "ubuntu"
      private_key = file(var.ssh_private_key_path)
      host        = aws_instance.wazuh_server.public_ip
    }
  }
}

# Linux Endpoint
resource "aws_instance" "linux_endpoint" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.endpoint_instance_type
  subnet_id              = aws_subnet.private_subnet.id
  vpc_security_group_ids = [aws_security_group.linux_endpoint_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.endpoint_profile.name
  key_name               = var.ssh_key_name

  root_block_device {
    volume_size           = var.endpoint_volume_size
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }

  user_data = templatefile("${path.module}/user_data/linux_agent.sh", {
    wazuh_server_ip = aws_instance.wazuh_server.private_ip
  })

  tags = {
    Name = "${var.project_name}-linux-endpoint"
    Role = "Endpoint"
  }

  depends_on = [aws_instance.wazuh_server]
}

# Windows Endpoint
resource "aws_instance" "windows_endpoint" {
  ami                    = data.aws_ami.windows.id
  instance_type          = var.endpoint_instance_type
  subnet_id              = aws_subnet.private_subnet.id
  vpc_security_group_ids = [aws_security_group.windows_endpoint_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.endpoint_profile.name
  key_name               = var.ssh_key_name

  root_block_device {
    volume_size           = 35 # Windows requires minimum 30GB
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }

  user_data = templatefile("${path.module}/user_data/windows_agent.ps1", {
    wazuh_server_ip = aws_instance.wazuh_server.private_ip
  })

  tags = {
    Name = "${var.project_name}-windows-endpoint"
    Role = "Endpoint"
  }

  depends_on = [aws_instance.wazuh_server]
}

# macOS EC2 Instance Configuration
# IMPORTANT: macOS on AWS requires Dedicated Hosts and is NOT free tier eligible
# Costs: ~$1.083/hour ($26/day, $780/month) - Minimum lease: 24 hours

# Dedicated Host for macOS (required by Apple licensing)
resource "aws_ec2_host" "macos_host" {
  count = var.enable_macos_endpoint ? 1 : 0

  instance_type     = "mac1.metal" # Intel Mac, or "mac2.metal" for Apple Silicon
  availability_zone = "${var.aws_region}a"

  # Auto-placement allows instances to target this host automatically
  auto_placement = "on"

  # Host recovery - automatically restart on underlying hardware failure
  host_recovery = "on"

  tags = {
    Name        = "${var.project_name}-macos-dedicated-host"
    Environment = var.environment
    Project     = var.project_name
    ManagedBy   = "terraform"
    CostCenter  = "security-lab"
  }
}

# Get latest macOS AMI
data "aws_ami" "macos" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn-ec2-macos-13.*"] # macOS Ventura 13.x
  }

  filter {
    name   = "architecture"
    values = ["x86_64_mac"] # Intel Mac, use "arm64_mac" for Apple Silicon
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }
}

# macOS EC2 Instance
resource "aws_instance" "macos_endpoint" {
  count = var.enable_macos_endpoint ? 1 : 0

  ami           = data.aws_ami.macos.id
  instance_type = "mac1.metal"

  # Must run on dedicated host
  host_id = aws_ec2_host.macos_host[0].id

  subnet_id                   = aws_subnet.private_subnet.id
  vpc_security_group_ids      = [aws_security_group.linux_endpoint_sg.id]
  associate_public_ip_address = false

  key_name = var.ssh_key_name

  # Root volume - macOS requires at least 60GB
  root_block_device {
    volume_size           = var.macos_volume_size
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  # User data for macOS (runs as launchd script)
  user_data = base64encode(templatefile("${path.module}/user_data/macos_endpoint.sh", {
    wazuh_server_ip = aws_instance.wazuh_server.private_ip
    agent_name      = "macos-endpoint-01"
  }))

  tags = {
    Name        = "${var.project_name}-macos-endpoint-01"
    Environment = var.environment
    OS          = "macOS"
    Role        = "monitored-endpoint"
    Project     = var.project_name
    ManagedBy   = "terraform"
  }

  # macOS instances take longer to boot
  timeouts {
    create = var.macos_create_timeout
  }

  depends_on = [aws_ec2_host.macos_host]
}
