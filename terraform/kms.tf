# terraform/kms.tf
# Customer-managed KMS key for PHI at rest (GAP-01, GAP-02) and the evidence vault.
# HIPAA 164.312(a)(2)(iv) — Encryption and decryption.

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "aws_kms_key" "phi" {
  description             = "Acme Health PHI CMK — S3 uploads, DynamoDB intake, evidence vault"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableAccountAdmin"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid    = "AllowServiceUse"
        Effect = "Allow"
        Principal = {
          Service = [
            "s3.amazonaws.com",
            "dynamodb.amazonaws.com",
            "cloudtrail.amazonaws.com"
          ]
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowCloudWatchLogs"
        Effect = "Allow"
        Principal = {
          Service = "logs.us-east-1.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey",
          "kms:ReEncrypt*"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:us-east-1:560599485314:log-group:*"
          }
        }
      }
    ]
  })

  tags = {
    Project   = "acme-health-intake"
    Workload  = "patient-intake-api"
    DataClass = "phi"
    ManagedBy = "terraform"
  }
}

resource "aws_kms_alias" "phi" {
  name          = "alias/acme-health-phi"
  target_key_id = aws_kms_key.phi.key_id
}

output "phi_kms_key_arn" {
  description = "CMK ARN referenced by S3 SSE, DynamoDB SSE, and the evidence vault"
  value       = aws_kms_key.phi.arn
}