# Security Group for Wazuh Server
resource "aws_security_group" "wazuh_server_sg" {
  name        = "${var.project_name}-wazuh-server-sg"
  description = "Security group for Wazuh server"
  vpc_id      = aws_vpc.soc_vpc.id

  # SSH access (restricted to your IP)
  ingress {
    description = "SSH from allowed IPs"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_ssh_cidr
  }

  # Wazuh Dashboard HTTPS
  ingress {
    description = "Wazuh Dashboard"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_ssh_cidr
  }

  # Wazuh agent enrollment
  ingress {
    description = "Wazuh agent enrollment"
    from_port   = 1514
    to_port     = 1514
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  # Wazuh agent communication
  ingress {
    description = "Wazuh agent communication"
    from_port   = 1515
    to_port     = 1515
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  # Wazuh API
  ingress {
    description = "Wazuh API"
    from_port   = 55000
    to_port     = 55000
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  # Allow all outbound
  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-wazuh-server-sg"
  }
}

# Security Group for Linux Endpoint
resource "aws_security_group" "linux_endpoint_sg" {
  name        = "${var.project_name}-linux-endpoint-sg"
  description = "Security group for Linux endpoint"
  vpc_id      = aws_vpc.soc_vpc.id

  # SSH from Wazuh server only (bastion pattern)
  ingress {
    description     = "SSH from Wazuh server"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.wazuh_server_sg.id]
  }

  # Allow all outbound
  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-linux-endpoint-sg"
  }
}

# Security Group for Windows Endpoint
resource "aws_security_group" "windows_endpoint_sg" {
  name        = "${var.project_name}-windows-endpoint-sg"
  description = "Security group for Windows endpoint"
  vpc_id      = aws_vpc.soc_vpc.id

  # RDP from Wazuh server only
  ingress {
    description     = "RDP from Wazuh server"
    from_port       = 3389
    to_port         = 3389
    protocol        = "tcp"
    security_groups = [aws_security_group.wazuh_server_sg.id]
  }

  # WinRM for management
  ingress {
    description     = "WinRM from Wazuh server"
    from_port       = 5985
    to_port         = 5986
    protocol        = "tcp"
    security_groups = [aws_security_group.wazuh_server_sg.id]
  }

  # Allow all outbound
  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-windows-endpoint-sg"
  }
}
