variable "aws_region" {
  description = "AWS region for SOC infrastructure"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "lab"
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "cloud-native-soc-platform"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR block for public subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "private_subnet_cidr" {
  description = "CIDR block for private subnet"
  type        = string
  default     = "10.0.2.0/24"
}

variable "allowed_ssh_cidr" {
  description = "CIDR blocks allowed to SSH (YOUR IP ONLY)"
  type        = list(string)
  default     = ["[ALLOWED_IP_ADDRESSES]"] # Your public or allowed IP(s)
}

variable "wazuh_instance_type" {
  description = "EC2 instance type for Wazuh server"
  type        = string
  default     = "t3.medium" # Required for Wazuh (2 vCPU, 4GB RAM) - Not Free Tier but necessary
}

variable "endpoint_instance_type" {
  description = "EC2 instance type for endpoints"
  type        = string
  default     = "t3.micro" # Free Tier eligible
}

variable "ssh_key_name" {
  description = "SSH key pair name"
  type        = string
  default     = "cloud-soc-key"
}

variable "ssh_private_key_path" {
  description = "Path to SSH private key for provisioner connections"
  type        = string
  default     = "~/.ssh/cloud-soc-key.pem"
}

variable "enable_macos_endpoint" {
  description = "Enable macOS endpoint (requires dedicated host, NOT free tier)"
  type        = bool
  default     = false
}

variable "wazuh_volume_size" {
  description = "Root volume size for Wazuh server (GB)"
  type        = number
  default     = 30
}

variable "endpoint_volume_size" {
  description = "Root volume size for endpoints (GB)"
  type        = number
  default     = 10
}

variable "macos_volume_size" {
  description = "Root volume size for macOS endpoint (GB)"
  type        = number
  default     = 100
}

variable "wazuh_init_wait_seconds" {
  description = "Seconds to wait for Wazuh initialization"
  type        = number
  default     = 120
}

variable "macos_create_timeout" {
  description = "Timeout for macOS instance creation"
  type        = string
  default     = "30m"
}

variable "enable_cloudtrail_wazuh_ingestion" {
  description = "Enable CloudTrail management event delivery to S3 and native Wazuh aws-s3 ingestion."
  type        = bool
  default     = true
}

variable "cloudtrail_log_retention_days" {
  description = "Number of days to retain CloudTrail objects in the Wazuh ingestion S3 bucket. Keep short for free-tier-conscious labs."
  type        = number
  default     = 14

  validation {
    condition     = var.cloudtrail_log_retention_days >= 1
    error_message = "cloudtrail_log_retention_days must be at least 1."
  }
}

variable "cloudtrail_multi_region" {
  description = "Create a multi-region CloudTrail trail. Disabled by default to reduce lab log volume and S3 usage."
  type        = bool
  default     = false
}
