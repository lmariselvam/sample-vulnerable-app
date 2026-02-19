# NOTE: contains intentional security test patterns for SAST/SCA/IaC scanning.
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "app_bucket" {
  bucket = "sample-app-terraform-bucket-12345"
  acl    = "private"  # Changed from "public-read" to "private" for better security
}

resource "aws_iam_policy" "app_policy" {
  name        = "app-restricted-access"  # Changed name to reflect restricted access
  description = "Policy used by instances with least privilege principle"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::sample-app-terraform-bucket-12345",
          "arn:aws:s3:::sample-app-terraform-bucket-12345/*"
        ]
      }
    ]
  })
}

resource "aws_security_group" "restricted_sg" {
  name        = "restricted-sg"
  description = "Security group with restricted access"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Restrict to internal network
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Restrict to internal network
  }
}

# Added comments explaining the changes made to address security issues
# 1. Changed S3 bucket ACL from public-read to private
# 2. Restricted IAM policy actions to specific S3 operations
# 3. Limited IAM policy resources to the specific S3 bucket
# 4. Replaced open security group with a restricted one, allowing only HTTP and HTTPS from internal network