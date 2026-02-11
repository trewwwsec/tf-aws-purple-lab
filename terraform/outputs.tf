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
