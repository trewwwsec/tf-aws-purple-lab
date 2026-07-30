data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

locals {
  cloudtrail_resource_count = var.enable_cloudtrail_wazuh_ingestion ? 1 : 0
  cloudtrail_name           = "${var.project_name}-${var.environment}-management-events"
  cloudtrail_bucket_name    = substr(lower(replace("${var.project_name}-${var.environment}-cloudtrail-${data.aws_caller_identity.current.account_id}-${var.aws_region}", "_", "-")), 0, 63)
  cloudtrail_source_arn     = "arn:${data.aws_partition.current.partition}:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${local.cloudtrail_name}"
  cloudtrail_log_prefix     = "AWSLogs/${data.aws_caller_identity.current.account_id}/*"
}

resource "aws_s3_bucket" "cloudtrail_logs" {
  count = local.cloudtrail_resource_count

  bucket = local.cloudtrail_bucket_name

  tags = {
    Name = local.cloudtrail_bucket_name
    Role = "cloudtrail-wazuh-ingestion"
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  count = local.cloudtrail_resource_count

  bucket                  = aws_s3_bucket.cloudtrail_logs[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "cloudtrail_logs" {
  count = local.cloudtrail_resource_count

  bucket = aws_s3_bucket.cloudtrail_logs[0].id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  count = local.cloudtrail_resource_count

  bucket = aws_s3_bucket.cloudtrail_logs[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  count = local.cloudtrail_resource_count

  bucket = aws_s3_bucket.cloudtrail_logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail_logs" {
  count = local.cloudtrail_resource_count

  bucket = aws_s3_bucket.cloudtrail_logs[0].id

  rule {
    id     = "expire-cloudtrail-logs"
    status = "Enabled"

    filter {
      prefix = "AWSLogs/"
    }

    expiration {
      days = var.cloudtrail_log_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.cloudtrail_log_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.cloudtrail_logs]
}

resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  count = local.cloudtrail_resource_count

  bucket = aws_s3_bucket.cloudtrail_logs[0].id
  policy = data.aws_iam_policy_document.cloudtrail_bucket[0].json

  depends_on = [
    aws_s3_bucket_public_access_block.cloudtrail_logs,
    aws_s3_bucket_ownership_controls.cloudtrail_logs
  ]
}

data "aws_iam_policy_document" "cloudtrail_bucket" {
  count = local.cloudtrail_resource_count

  statement {
    sid = "AWSCloudTrailAclCheck"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail_logs[0].arn]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.cloudtrail_source_arn]
    }
  }

  statement {
    sid = "AWSCloudTrailWrite"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.cloudtrail_logs[0].arn}/${local.cloudtrail_log_prefix}"
    ]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.cloudtrail_source_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_cloudtrail" "management_events" {
  count = local.cloudtrail_resource_count

  name                          = local.cloudtrail_name
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs[0].id
  include_global_service_events = true
  is_multi_region_trail         = var.cloudtrail_multi_region
  enable_log_file_validation    = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  tags = {
    Name = local.cloudtrail_name
    Role = "aws-api-audit"
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail_logs]
}
