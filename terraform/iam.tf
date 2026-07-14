locals {
  ec2_assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# IAM role for Wazuh server
resource "aws_iam_role" "wazuh_server_role" {
  name = "${var.project_name}-wazuh-server-role"

  assume_role_policy = local.ec2_assume_role_policy

  tags = {
    Name = "${var.project_name}-wazuh-server-role"
  }
}

# Attach CloudWatch Logs policy for monitoring
resource "aws_iam_role_policy_attachment" "wazuh_cloudwatch" {
  role       = aws_iam_role.wazuh_server_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# Instance profile for Wazuh server
resource "aws_iam_instance_profile" "wazuh_server_profile" {
  name = "${var.project_name}-wazuh-server-profile"
  role = aws_iam_role.wazuh_server_role.name
}

# IAM role for endpoints (minimal permissions)
resource "aws_iam_role" "endpoint_role" {
  name = "${var.project_name}-endpoint-role"

  assume_role_policy = local.ec2_assume_role_policy

  tags = {
    Name = "${var.project_name}-endpoint-role"
  }
}

# Instance profile for endpoints
resource "aws_iam_instance_profile" "endpoint_profile" {
  name = "${var.project_name}-endpoint-profile"
  role = aws_iam_role.endpoint_role.name
}

# Allow Wazuh to ingest CloudTrail management events from the dedicated S3 bucket.
resource "aws_iam_role_policy" "wazuh_cloudtrail_ingestion" {
  count = local.cloudtrail_resource_count

  name = "${var.project_name}-wazuh-cloudtrail-ingestion"
  role = aws_iam_role.wazuh_server_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ListCloudTrailBucket"
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = aws_s3_bucket.cloudtrail_logs[0].arn
        Condition = {
          StringLike = {
            "s3:prefix" = [
              local.cloudtrail_log_prefix
            ]
          }
        }
      },
      {
        Sid    = "ReadCloudTrailObjects"
        Effect = "Allow"
        Action = [
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.cloudtrail_logs[0].arn}/${local.cloudtrail_log_prefix}"
      }
    ]
  })
}
