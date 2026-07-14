terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Uncomment and configure for remote state with encryption and locking:
  # backend "s3" {
  #   bucket         = "tf-state-<account-id>-<region>"
  #   key            = "cloud-soc/terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   dynamodb_table = "terraform-state-lock"
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "cloud-native-soc-platform"
      ManagedBy   = "Terraform"
      Environment = var.environment
      Owner       = "cloud-soc-admin"
    }
  }
}
