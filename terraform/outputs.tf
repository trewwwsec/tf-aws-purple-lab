output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.soc_vpc.id
}

output "wazuh_server_public_ip" {
  description = "Wazuh server public IP"
  value       = aws_instance.wazuh_server.public_ip
}

output "wazuh_server_private_ip" {
  description = "Wazuh server private IP"
  value       = aws_instance.wazuh_server.private_ip
}

output "linux_endpoint_private_ip" {
  description = "Linux endpoint private IP"
  value       = aws_instance.linux_endpoint.private_ip
}

output "windows_endpoint_private_ip" {
  description = "Windows endpoint private IP"
  value       = aws_instance.windows_endpoint.private_ip
}

output "wazuh_dashboard_url" {
  description = "Wazuh dashboard URL"
  value       = "https://${aws_instance.wazuh_server.public_ip}"
}

output "ssh_commands" {
  description = "SSH connection commands"
  value = {
    wazuh_server   = "ssh -i ~/.ssh/${var.ssh_key_name}.pem ubuntu@${aws_instance.wazuh_server.public_ip}"
    linux_endpoint = "ssh -i ~/.ssh/${var.ssh_key_name}.pem -J ubuntu@${aws_instance.wazuh_server.public_ip} ubuntu@${aws_instance.linux_endpoint.private_ip}"
  }
}

output "setup_summary" {
  description = "Quick reference for next steps"
  value = {
    wazuh_dashboard = "https://${aws_instance.wazuh_server.public_ip}"
    get_credentials = "Run: ./scripts/get-wazuh-info.sh"
    next_steps      = "1) Wait ~10 min for installation, 2) Run ./scripts/get-wazuh-info.sh, 3) Access dashboard, 4) Configure detection rules"
  }
}

output "macos_endpoint_private_ip" {
  description = "Private IP of macOS endpoint (if enabled)"
  value       = var.enable_macos_endpoint ? aws_instance.macos_endpoint[0].private_ip : "Not enabled - set enable_macos_endpoint = true to deploy"
}

output "macos_dedicated_host_id" {
  description = "Dedicated Host ID for macOS (if enabled)"
  value       = var.enable_macos_endpoint ? aws_ec2_host.macos_host[0].id : "Not enabled - set enable_macos_endpoint = true to deploy"
}

output "macos_cost_warning" {
  description = "Cost warning for macOS endpoint"
  value       = var.enable_macos_endpoint ? "WARNING: $1.083/hour (~$26/day, ~$780/month) - DESTROY WHEN NOT IN USE!" : "macOS endpoint not enabled (no cost)"
}

output "cloudtrail_wazuh_ingestion" {
  description = "CloudTrail to Wazuh ingestion resources and free-tier-conscious cost notes"
  value = var.enable_cloudtrail_wazuh_ingestion ? {
    enabled        = true
    bucket_name    = aws_s3_bucket.cloudtrail_logs[0].id
    trail_arn      = aws_cloudtrail.management_events[0].arn
    retention_days = var.cloudtrail_log_retention_days
    multi_region   = var.cloudtrail_multi_region
    cost_note      = "CloudTrail management events use the first-copy management event path; S3 storage/request charges still apply. Data events, Insights, GuardDuty, and VPC Flow Logs are not enabled by this PR."
    } : {
    enabled        = false
    bucket_name    = null
    trail_arn      = null
    retention_days = null
    multi_region   = null
    cost_note      = "CloudTrail to Wazuh ingestion is disabled."
  }
}
